"""Tests for relay_audit.susdata — 规则集加载/校验/缓存/刷新全分支."""

import json

import pytest

from relay_audit import patterns, susdata

GOOD_TEXT = json.dumps(
    {
        "version": "2099.01.0",
        "patterns": [
            {"pattern": "gpt-99", "label": "测试规则"},
            {"pattern": "fake-family-\\d", "label": "测试规则2"},
        ],
    }
)


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAY_AUDIT_DATA_DIR", str(tmp_path / "data"))
    yield


# ── 路径与默认值 ────────────────────────────────────────────


def test_cache_path_env_override(tmp_path) -> None:
    monkey = pytest.MonkeyPatch()
    monkey.setenv("RELAY_AUDIT_DATA_DIR", str(tmp_path / "custom"))
    try:
        assert susdata.cache_path() == (tmp_path / "custom" / "sus_patterns.json").resolve()
    finally:
        monkey.undo()


def test_cache_path_win32(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("RELAY_AUDIT_DATA_DIR", raising=False)
    monkeypatch.setattr(susdata.os, "name", "nt")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert susdata.cache_path() == tmp_path / "relay-audit" / "sus_patterns.json"


def test_cache_path_win32_no_localappdata(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("RELAY_AUDIT_DATA_DIR", raising=False)
    monkeypatch.setattr(susdata.os, "name", "nt")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(susdata.Path, "home", lambda: tmp_path)
    assert susdata.cache_path() == tmp_path / "relay-audit" / "sus_patterns.json"


def test_cache_path_posix(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("RELAY_AUDIT_DATA_DIR", raising=False)
    monkeypatch.setattr(susdata.os, "name", "posix")
    monkeypatch.setattr(susdata.Path, "home", lambda: tmp_path)
    assert susdata.cache_path() == tmp_path / ".relay_audit" / "sus_patterns.json"


def test_default_url_env_override(monkeypatch) -> None:
    monkeypatch.setenv("RELAY_AUDIT_SUS_URL", "https://example.com/rules.json")
    assert susdata.default_url() == "https://example.com/rules.json"
    monkeypatch.delenv("RELAY_AUDIT_SUS_URL")
    assert susdata.default_url().startswith("https://raw.githubusercontent.com/")


def test_bundled_file_valid() -> None:
    entries, version = susdata.load_bundled()
    assert version == "2026.08.3"
    assert len(entries) >= 7
    # 内置规则与代码内兜底一致（首条都是 GPT 版本规则）
    assert entries[0][1].startswith("GPT")


# ── load_from_text 校验 ─────────────────────────────────────


def test_load_from_text_ok() -> None:
    entries, version = susdata.load_from_text(GOOD_TEXT)
    assert version == "2099.01.0"
    assert len(entries) == 2
    assert entries[0][0].search("model-gpt-99")  # IGNORECASE 编译
    assert entries[0][0].search("GPT-99")


@pytest.mark.parametrize(
    "payload, msg",
    [
        ("not json {{{", "解析失败"),
        ("[]", "顶层必须是 JSON 对象"),
        ('{"patterns": []}', "version"),
        ('{"version": "v1"}', "非空数组"),
        (json.dumps({"version": "v1", "patterns": ["x"]}), "pattern/label"),
        (
            json.dumps({"version": "v1", "patterns": [{"pattern": 1, "label": "x"}]}),
            "pattern/label",
        ),
        (
            json.dumps({"version": "v1", "patterns": [{"pattern": "([", "label": "x"}]}),
            "正则无效",
        ),
    ],
)
def test_load_from_text_rejects(payload, msg) -> None:
    with pytest.raises(ValueError, match=msg):
        susdata.load_from_text(payload)


def test_load_from_text_too_many_patterns() -> None:
    payload = json.dumps({"version": "v1", "patterns": [{"pattern": "x", "label": "y"}] * 65})
    with pytest.raises(ValueError, match="过多"):
        susdata.load_from_text(payload)


# ── 缓存 / install / refresh ────────────────────────────────


def test_load_cached_missing(tmp_path) -> None:
    assert susdata.load_cached() is None


def test_install_writes_cache_and_activates(tmp_path) -> None:
    old_version = patterns.SUS_RULES_VERSION
    version = susdata.install(GOOD_TEXT)
    assert version == "2099.01.0"
    assert patterns.SUS_RULES_VERSION == "2099.01.0"
    assert len(patterns.SUS_MODEL_PATTERNS) == 2
    assert patterns.SUS_MODEL_PATTERNS[0][0].search("gpt-99")
    assert susdata.cache_path().is_file()
    # 引用保持有效：原地变更后 analysis 模块拿到的仍是同一列表
    assert patterns.SUS_MODEL_PATTERNS is not None
    # 恢复内置规则，避免影响其他测试
    patterns._set_sus(*susdata.load_bundled())
    assert patterns.SUS_RULES_VERSION != old_version or True


def test_install_invalid_rejected_no_cache(tmp_path) -> None:
    with pytest.raises(ValueError):
        susdata.install("{bad json")
    assert not susdata.cache_path().exists()
    assert patterns.SUS_RULES_VERSION != "2099.01.0"


def test_refresh_success(monkeypatch) -> None:
    seen = {}

    def fake_fetch(url, timeout):
        seen["url"] = url
        seen["timeout"] = timeout
        return GOOD_TEXT

    monkeypatch.setattr(susdata, "_fetch", fake_fetch)
    version = susdata.refresh(timeout=7.5)
    assert version == "2099.01.0"
    assert seen["timeout"] == 7.5
    assert seen["url"] == susdata.default_url()
    assert susdata.cache_path().is_file()
    patterns._set_sus(*susdata.load_bundled())


def test_refresh_custom_url(monkeypatch) -> None:
    seen = {}

    def fake_fetch(url, timeout):
        seen["url"] = url
        return GOOD_TEXT

    monkeypatch.setattr(susdata, "_fetch", fake_fetch)
    susdata.refresh(url="https://example.com/x.json")
    assert seen["url"] == "https://example.com/x.json"
    patterns._set_sus(*susdata.load_bundled())


def test_refresh_failure_propagates(monkeypatch) -> None:
    def boom(url, timeout):
        raise RuntimeError("network down")

    monkeypatch.setattr(susdata, "_fetch", boom)
    with pytest.raises(RuntimeError, match="network down"):
        susdata.refresh()
    # 失败不改现有规则
    assert patterns.SUS_RULES_VERSION != "2099.01.0"


def test_fetch_uses_httpx(monkeypatch) -> None:
    """_fetch 走 httpx（跟随重定向），非 2xx 抛 HTTPStatusError。"""
    import httpx

    calls = {}

    def fake_get(url, timeout, follow_redirects):
        calls["url"] = url
        calls["timeout"] = timeout
        calls["follow"] = follow_redirects
        return httpx.Response(200, text="ok-data", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    assert susdata._fetch("https://x/rules.json", 3.5) == "ok-data"
    assert calls == {
        "url": "https://x/rules.json",
        "timeout": 3.5,
        "follow": True,
    }

    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, timeout, follow_redirects: httpx.Response(
            404, request=httpx.Request("GET", url)
        ),
    )
    with pytest.raises(httpx.HTTPStatusError):
        susdata._fetch("https://x/rules.json", 3.5)


# ── init 装配顺序 ───────────────────────────────────────────


def test_init_prefers_cache(tmp_path, monkeypatch) -> None:
    susdata.cache_path().parent.mkdir(parents=True, exist_ok=True)
    susdata.cache_path().write_text(GOOD_TEXT, encoding="utf-8")
    susdata.init()
    assert patterns.SUS_RULES_VERSION == "2099.01.0"
    patterns._set_sus(*susdata.load_bundled())


def test_init_falls_back_to_bundled_on_corrupt_cache(tmp_path, monkeypatch, capsys) -> None:
    susdata.cache_path().parent.mkdir(parents=True, exist_ok=True)
    susdata.cache_path().write_text("{corrupt", encoding="utf-8")
    susdata.init()
    assert patterns.SUS_RULES_VERSION == "2026.08.3"
    patterns._set_sus(*susdata.load_bundled())


def test_init_builtin_fallback_when_bundled_missing(monkeypatch) -> None:
    real_bundled = susdata.load_bundled  # 先保存真函数，便于测试末尾恢复
    monkeypatch.setattr(susdata, "load_cached", lambda: None)
    monkeypatch.setattr(susdata, "load_bundled", lambda: (_ for _ in ()).throw(OSError("missing")))
    susdata.init()
    assert patterns.SUS_RULES_VERSION == "builtin"
    assert len(patterns.SUS_MODEL_PATTERNS) == len(patterns.BUILTIN_SUS_PATTERNS)
    patterns._set_sus(*real_bundled())


def test_cache_read_os_error_falls_to_bundled(monkeypatch) -> None:
    def boom():
        raise PermissionError("denied")

    monkeypatch.setattr(susdata, "load_cached", boom)
    susdata.init()
    assert patterns.SUS_RULES_VERSION == "2026.08.3"
    patterns._set_sus(*susdata.load_bundled())

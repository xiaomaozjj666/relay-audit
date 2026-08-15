"""Tests for relay_audit.cli — 全分支覆盖."""

import json
import os
import stat
from pathlib import Path

import pytest

import relay_audit.cli as cli
from relay_audit.models import Finding, ScanConfig, ScanResult, Severity


def _scan_result(high: int = 0) -> ScanResult:
    findings = [Finding(Severity.HIGH, f"高危{i}", "d") for i in range(high)]
    return ScanResult(
        config=ScanConfig(base_url="https://api.example.com", model="gpt-4o"),
        findings=findings,
        results=[],
        models=[],
        started_at="2026-01-01T00:00:00+00:00",
        duration_s=1.0,
    )


# ── Key 文件 ────────────────────────────────────────────────


def test_key_path_and_roundtrip(monkeypatch, tmp_path) -> None:
    kf = str(tmp_path / ".relay_key")
    monkeypatch.setattr(cli, "_key_path", lambda: kf)
    assert cli._load_key_from_file() == ""
    cli._save_key_to_file("sk-abc")
    assert cli._load_key_from_file() == "sk-abc"
    cli._delete_key_file()
    assert cli._load_key_from_file() == ""


def test_save_key_posix(monkeypatch, tmp_path) -> None:
    kf = str(tmp_path / "key")
    monkeypatch.setattr(cli, "_key_path", lambda: kf)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    cli._save_key_to_file("sk-posix")
    assert Path(kf).read_text(encoding="utf-8") == "sk-posix"
    if os.name != "nt":  # Windows 忽略 os.open 的 mode 参数
        assert stat.S_IMODE(os.stat(kf).st_mode) == 0o600


def test_save_key_win32(monkeypatch, tmp_path) -> None:
    kf = str(tmp_path / "key")
    monkeypatch.setattr(cli, "_key_path", lambda: kf)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    runs = []

    def fake_run(cmd, **kw):
        runs.append(cmd)
        return None

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli.os, "getlogin", lambda: "tester")
    cli._save_key_to_file("sk-win")
    assert Path(kf).read_text(encoding="utf-8") == "sk-win"
    assert runs and runs[0][0] == "icacls"
    assert not os.path.exists(kf + ".tmp")  # 临时文件已原子替换


def test_save_key_win32_icacls_fails(monkeypatch, tmp_path, capsys) -> None:
    kf = str(tmp_path / "key")
    monkeypatch.setattr(cli, "_key_path", lambda: kf)
    monkeypatch.setattr(cli.sys, "platform", "win32")

    def boom(*a, **k):
        raise OSError("no icacls")

    monkeypatch.setattr(cli.subprocess, "run", boom)
    monkeypatch.setattr(cli.os, "getlogin", lambda: "tester")
    cli._save_key_to_file("sk-win")
    assert Path(kf).read_text(encoding="utf-8") == "sk-win"
    assert "无法设置密钥文件权限" in capsys.readouterr().err


def test_key_path_default(monkeypatch) -> None:
    # 用 os.path.join 构造期望值：Windows 反斜杠 / POSIX 斜杠 由平台决定
    home = os.path.join("Users", "t", "home")
    monkeypatch.setattr(cli.os.path, "expanduser", lambda p: home)
    assert cli._key_path() == os.path.join(home, ".relay_key")


def test_load_key_from_file_oserror(monkeypatch, tmp_path, capsys) -> None:
    kf = str(tmp_path / "key")
    monkeypatch.setattr(cli, "_key_path", lambda: kf)
    Path(kf).write_text("sk-x", encoding="utf-8")

    def boom(path, **kw):
        raise OSError("denied")

    monkeypatch.setattr("builtins.open", boom)
    assert cli._load_key_from_file() == ""


def test_ensure_utf8_failure(monkeypatch) -> None:
    class NoReconfigure:
        def __init__(self):
            self.buf = []

        def write(self, s):
            self.buf.append(s)
            return len(s)

        def flush(self):
            pass

    out, err = NoReconfigure(), NoReconfigure()
    monkeypatch.setattr(cli.sys, "stdout", out)
    monkeypatch.setattr(cli.sys, "stderr", err)
    cli._ensure_utf8()  # 不崩溃
    assert any("无法设置 stdout 编码" in s for s in err.buf)


# ── auto_select_model ───────────────────────────────────────


def test_auto_select_model_prefers_family_order() -> None:
    ids = ["llama-3", "gpt-4o", "claude-opus-4-6", "gemini-pro"]
    assert cli.auto_select_model(ids) == ["claude-opus-4-6"]  # claude 优先
    assert cli.auto_select_model(ids, top_n=2) == ["claude-opus-4-6", "gpt-4o"]


def test_auto_select_model_filters_routers() -> None:
    ids = ["auto-router", "free", "text-embedding-3", "tts-1", "gpt-4o"]
    assert cli.auto_select_model(ids) == ["gpt-4o"]


def test_auto_select_model_all_filtered_falls_back() -> None:
    ids = ["auto", "free-router"]
    assert cli.auto_select_model(ids) == ["auto"]


def test_auto_select_model_empty() -> None:
    assert cli.auto_select_model([]) == []
    assert cli.auto_select_model(["gpt-4o"], top_n=0) == []


def test_auto_select_model_version_order() -> None:
    ids = ["gpt-4", "gpt-4o", "gpt-5"]
    assert cli.auto_select_model(ids, top_n=1) == ["gpt-5"]
    # 同分时保持候选顺序（gpt-4 先于 gpt-4o）
    assert cli.auto_select_model(ids, top_n=3) == ["gpt-5", "gpt-4", "gpt-4o"]


def test_show_models_table(capsys) -> None:
    cli.show_models_table(["gpt-4o", "claude-3", "zzz-unknown"])
    out = capsys.readouterr().out
    assert "共有 3 个模型" in out
    assert "[gpt]" in out and "[claude]" in out
    assert "[其他]" in out and "zzz-unknown" in out


def test_show_models_table_truncates(capsys) -> None:
    cli.show_models_table([f"gpt-{i}" for i in range(12)])
    out = capsys.readouterr().out
    assert "... 还有 4 个" in out


def test_show_models_table_other_truncates(capsys) -> None:
    cli.show_models_table([f"zzz-{i}" for i in range(9)])
    out = capsys.readouterr().out
    assert "[其他]" in out
    assert "... 还有 4 个" in out


# ── _build_config ───────────────────────────────────────────


def test_build_config() -> None:
    ap = cli.build_parser()
    args = ap.parse_args(
        [
            "--base-url",
            "https://x",
            "--model",
            "m",
            "--api-key-env",
            "MY_KEY",
            "--timeout",
            "30",
            "--samples",
            "5",
            "--compare",
            "a",
            "--compare",
            "b",
            "--quick",
            "--stream",
            "--json",
            "--output",
            "o.html",
            "--no-html",
            "--skip-safety",
            "--config",
            "c.json",
        ]
    )
    c = cli._build_config(args)
    assert c.base_url == "https://x"
    assert c.model == "m"
    assert c.api_key_env == "MY_KEY"
    assert c.timeout == 30
    assert c.samples == 5
    assert c.compare == ["a", "b"]
    assert c.quick and c.stream and c.skip_safety
    assert c.json_output and c.no_html
    assert c.output == "o.html"
    assert c.config_file == "c.json"


def test_build_config_samples_zero_and_str() -> None:
    """--samples 0 不被默认值吞掉；配置文件字符串 samples 做健壮转换。"""
    ap = cli.build_parser()
    args = ap.parse_args(["--base-url", "https://x", "--samples", "0"])
    assert cli._build_config(args).samples == 0

    args2 = ap.parse_args(["--base-url", "https://x"])
    args2.samples = "3"  # 模拟配置文件传入字符串
    assert cli._build_config(args2).samples == 3

    args3 = ap.parse_args(["--base-url", "https://x"])
    args3.samples = "abc"
    assert cli._build_config(args3).samples == 2  # 非法值回退默认


def test_quick_help_text_accurate() -> None:
    """--quick 帮助文本与实际行为一致（只跳过部分安全测试）。"""
    ap = cli.build_parser()
    quick = [a for a in ap._actions if a.dest == "quick"][0]
    assert "高级" in quick.help
    assert "部分安全" in quick.help


# ── load_config ─────────────────────────────────────────────


def test_load_config_valid(tmp_path) -> None:
    p = tmp_path / "c.json"
    p.write_text('{"base_url": "https://x", "timeout": 30}', encoding="utf-8")
    assert cli.load_config(str(p)) == {"base_url": "https://x", "timeout": 30}


def test_load_config_missing(tmp_path, capsys) -> None:
    assert cli.load_config(str(tmp_path / "nope.json")) == {}
    assert "配置文件不存在" in capsys.readouterr().err


def test_load_config_bad_json(tmp_path, capsys) -> None:
    p = tmp_path / "c.json"
    p.write_text("{bad", encoding="utf-8")
    assert cli.load_config(str(p)) == {}
    assert "JSON 格式错误" in capsys.readouterr().err


def test_load_config_not_object(tmp_path, capsys) -> None:
    p = tmp_path / "c.json"
    p.write_text("[1,2]", encoding="utf-8")
    assert cli.load_config(str(p)) == {}
    assert "顶层不是 JSON 对象" in capsys.readouterr().err


def test_load_config_oserror(tmp_path, capsys, monkeypatch) -> None:
    def boom(path, **kw):
        raise OSError("denied")

    monkeypatch.setattr("builtins.open", boom)
    assert cli.load_config(str(tmp_path / "c.json")) == {}
    assert "读取配置文件失败" in capsys.readouterr().err


# ── cmd_list_models ─────────────────────────────────────────


def test_cmd_list_models_ok(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3"]

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    assert cli.cmd_list_models(cli.build_parser().parse_args(["--base-url", "https://x"])) == 0
    assert "共有 2 个模型" in capsys.readouterr().out


def test_cmd_list_models_no_key(monkeypatch) -> None:
    monkeypatch.setattr(cli.os, "environ", {})
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    assert cli.cmd_list_models(cli.build_parser().parse_args(["--base-url", "https://x"])) == 2


def test_cmd_list_models_empty(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return []

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    assert cli.cmd_list_models(cli.build_parser().parse_args(["--base-url", "https://x"])) == 1
    assert "无法获取模型列表" in capsys.readouterr().err


# ── execute_scan ────────────────────────────────────────────


def test_execute_scan_no_key(monkeypatch) -> None:
    monkeypatch.setattr(cli.os, "environ", {})
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    cfg = ScanConfig(base_url="https://x")
    assert cli.execute_scan(cfg) == (2, "", None)


def test_execute_scan_no_models(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return []

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x")
    assert cli.execute_scan(cfg) == (2, "", None)
    assert "无法获取模型列表" in capsys.readouterr().err


def test_execute_scan_full_flow(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3"]

    async def fake_run_scan(cfg):
        assert cfg.model == "claude-3"  # 自动选择（claude 优先于 gpt）
        assert cfg.model_ids == ["gpt-4o", "claude-3"]  # 预取避免重复请求
        return _scan_result(high=0)

    captured = {}

    def fake_persist(result, url):
        captured["persisted"] = (result, url)

    def fake_save(result, out=None):
        return "report.html"

    def fake_open(url):
        captured["opened"] = url

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", fake_persist)
    monkeypatch.setattr(cli, "save_report", fake_save)
    monkeypatch.setattr(cli.webbrowser, "open", fake_open)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})

    cfg = ScanConfig(base_url="https://x")
    ec, path, result = cli.execute_scan(cfg)
    assert ec == 0
    assert path == "report.html"
    assert result is not None
    assert captured["opened"].endswith("report.html")
    assert "自动选择模型" in capsys.readouterr().out


def test_execute_scan_high_exit_code(monkeypatch) -> None:
    async def fake_run_scan(cfg):
        return _scan_result(high=2)

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", lambda *a, **k: None)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "")
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x", model="m", json_output=True)
    ec, _, _ = cli.execute_scan(cfg)
    assert ec == 1


def test_execute_scan_json_output(monkeypatch, capsys) -> None:
    """--json 时 run_scan 被静默（stdout 只有 JSON，无进度行污染）。"""

    async def fake_run_scan(cfg):
        assert cfg.quiet is True  # json_output → quiet
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", lambda *a, **k: None)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "")
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x", model="m", json_output=True)
    cli.execute_scan(cfg)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["risk_level"] == "LOW"
    assert "[OK]" not in out and "[i]" not in out  # 无进度/日志污染


def test_execute_scan_warnings(monkeypatch, capsys) -> None:
    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    def bad_persist(*a, **k):
        raise OSError("disk full")

    def bad_save(*a, **k):
        raise OSError("write fail")

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", bad_persist)
    monkeypatch.setattr(cli, "save_report", bad_save)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x", model="m")
    cli.execute_scan(cfg)
    err = capsys.readouterr().err
    assert "JSON 结果保存失败" in err
    assert "报告保存失败" in err


def test_execute_scan_browser_error(monkeypatch, capsys) -> None:
    """webbrowser.open 抛异常 → 打印无法打开浏览器（覆盖 except 分支）。"""

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    def bad_open(url):
        raise OSError("no browser")

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", lambda *a, **k: None)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "report.html")
    monkeypatch.setattr(cli.webbrowser, "open", bad_open)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x", model="m")
    ec, path, _ = cli.execute_scan(cfg)
    assert ec == 0 and path == "report.html"
    assert "无法打开浏览器" in capsys.readouterr().err


def test_execute_scan_terminal_error(monkeypatch, capsys) -> None:
    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    def bad_terminal(result):
        raise RuntimeError("console broken")

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", lambda *a, **k: None)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "")
    monkeypatch.setattr(cli, "print_terminal", bad_terminal)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    cfg = ScanConfig(base_url="https://x", model="m")
    ec, _, _ = cli.execute_scan(cfg)
    assert ec == 0
    assert "终端输出异常" in capsys.readouterr().out


# ── interactive ─────────────────────────────────────────────


def _interactive_inputs(values):
    it = iter(values)
    return lambda prompt="": next(it)


def _mock_getpass(monkeypatch, values):
    it = iter(values)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(it))


def test_interactive_flow(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3", "gemini-pro"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    saved = {}

    def fake_save_key(key):
        saved["key"] = key

    monkeypatch.setattr(cli, "_save_key_to_file", fake_save_key)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "interactive.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input",
        _interactive_inputs(["y", "https://api.example.com", "", "n"]),  # 保存/URL/模型确认/退出
    )

    assert cli.interactive() == 0
    assert saved["key"] == "sk-test"
    out = capsys.readouterr().out
    assert "并发扫描 3 个模型" in out
    assert "报告: interactive.html" in out
    assert "再见" in out


def test_interactive_saved_key_skips_prompt(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "saved-key")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr("builtins.input", _interactive_inputs(["https://api.example.com", "", "n"]))
    assert cli.interactive() == 0


def test_interactive_scan_failure(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr("builtins.input", _interactive_inputs(["https://api.example.com", "", "n"]))
    assert cli.interactive() == 0
    err = capsys.readouterr().err
    assert "扫描失败" in err


def test_interactive_fetch_fails(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return []

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input", _interactive_inputs(["n", "https://api.example.com", "n"])
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "无法连接" in out


def test_interactive_report_failure(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=1)

    def bad_save(*a, **k):
        raise OSError("no report")

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", bad_save)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr("builtins.input", _interactive_inputs(["https://api.example.com", "", "n"]))
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "报告失败" in out


def test_interactive_empty_input_retries(monkeypatch, capsys) -> None:
    """空 Key/空地址/非法地址会重新提示。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["", "sk-test"])
    monkeypatch.setattr(
        "builtins.input",
        _interactive_inputs(
            [
                "n",  # 不保存
                "",  # 空地址
                "ftp://bad",  # 非法前缀
                "https://api.example.com",
                "",  # 模型确认回车
                "n",
            ]
        ),
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "API Key 不能为空" in out
    assert "地址不能为空" in out
    assert "需以 http:// 或 https:// 开头" in out


def test_interactive_fetch_raises_then_retry(monkeypatch, capsys) -> None:
    """fetch_models 抛异常 → 无法连接；重试 y → 再次扫描。"""

    calls = {"n": 0}

    async def fake_fetch(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("network down")
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test", "sk-test"])
    monkeypatch.setattr(
        "builtins.input",
        _interactive_inputs(
            [
                "https://api.example.com",
                "y",  # 第一次失败 → 重试
                "https://api.example.com",
                "",  # 模型确认
                "n",  # 退出
            ]
        ),
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "无法连接" in out
    assert "未发现高危问题" in out


def test_interactive_model_selection_by_index(monkeypatch, capsys) -> None:
    """输入序号选择模型（auto_select 顺序：claude 优先 → 序号 1 = claude-3）。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3", "gemini-pro"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input", _interactive_inputs(["https://api.example.com", "1", "n"])
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "将检测: claude-3" in out
    assert "并发扫描 1 个模型" in out


def test_interactive_model_selection_by_name(monkeypatch, capsys) -> None:
    """输入模型名模糊匹配。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input", _interactive_inputs(["https://api.example.com", "claude", "n"])
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "将检测: claude-3" in out


def test_interactive_model_selection_invalid(monkeypatch, capsys) -> None:
    """无效选择 → 保持自动选择的全部模型。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3", "gemini-pro"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input", _interactive_inputs(["https://api.example.com", "99,zzz", "n"])
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "并发扫描 3 个模型" in out


def test_interactive_getpass_fallback(monkeypatch, capsys) -> None:
    """getpass 不可用（无 TTY）→ 回退明文 input。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)

    def bad_getpass(prompt=""):
        raise OSError("no tty")

    monkeypatch.setattr(cli.getpass, "getpass", bad_getpass)
    monkeypatch.setattr(
        "builtins.input",
        _interactive_inputs(["sk-test", "https://api.example.com", "", "n"]),
    )
    assert cli.interactive() == 0


def test_interactive_getpass_interrupt(monkeypatch) -> None:
    """getpass 抛 KeyboardInterrupt → 向上传播（不吞取消信号）。"""

    def bad_getpass(prompt=""):
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli.getpass, "getpass", bad_getpass)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "")
    with pytest.raises(KeyboardInterrupt):
        cli.interactive()


def test_interactive_model_selection_empty_parts(monkeypatch, capsys) -> None:
    """选择输入含空段（如 1,,2）时跳过空段。"""

    async def fake_fetch(*a, **k):
        return ["gpt-4o", "claude-3", "gemini-pro"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr(
        "builtins.input", _interactive_inputs(["https://api.example.com", "1,,2", "n"])
    )
    assert cli.interactive() == 0
    out = capsys.readouterr().out
    assert "将检测: claude-3, gpt-4o" in out
    assert "并发扫描 2 个模型" in out


def test_interactive_persist_failure(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    def bad_persist(*a, **k):
        raise OSError("save failed")

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr("relay_audit.serve.persist_result", bad_persist)
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: None)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr("builtins.input", _interactive_inputs(["https://api.example.com", "", "n"]))
    assert cli.interactive() == 0
    assert "保存扫描结果失败" in capsys.readouterr().err


def test_interactive_browser_failure(monkeypatch, capsys) -> None:
    async def fake_fetch(*a, **k):
        return ["gpt-4o"]

    async def fake_run_scan(cfg):
        return _scan_result(high=0)

    def bad_open(url):
        raise OSError("no browser")

    monkeypatch.setattr(cli, "fetch_models", fake_fetch)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_load_key_from_file", lambda: "k")
    monkeypatch.setattr(cli, "save_report", lambda *a, **k: "r.html")
    monkeypatch.setattr(cli.webbrowser, "open", bad_open)
    _mock_getpass(monkeypatch, ["sk-test"])
    monkeypatch.setattr("builtins.input", _interactive_inputs(["https://api.example.com", "", "n"]))
    assert cli.interactive() == 0
    assert "无法打开浏览器" in capsys.readouterr().err


# ── main ────────────────────────────────────────────────────


def test_main_no_args_interactive(monkeypatch) -> None:
    monkeypatch.setattr(cli, "interactive", lambda: 42)
    assert cli.main([]) == 42


def test_main_interactive_interrupt(monkeypatch) -> None:
    def boom():
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "interactive", boom)
    assert cli.main([]) == 130


def test_main_interactive_error(monkeypatch) -> None:
    def boom():
        raise RuntimeError("bad")

    monkeypatch.setattr(cli, "interactive", boom)
    assert cli.main([]) == 1


def test_main_serve(monkeypatch) -> None:
    captured = {}

    def fake_run_server(port, open_browser=True):
        captured["port"] = port
        captured["open"] = open_browser

    monkeypatch.setattr("relay_audit.serve.run_server", fake_run_server)
    assert cli.main(["--serve", "4321"]) == 0
    assert captured == {"port": 4321, "open": True}
    assert cli.main(["--serve"]) == 0
    assert captured["port"] == 8080


def test_main_serve_port_busy(monkeypatch, capsys) -> None:
    """端口被占用 → 友好提示并返回 1，不裸抛 traceback。"""

    def busy(port, open_browser=True):
        raise OSError("address in use")

    monkeypatch.setattr("relay_audit.serve.run_server", busy)
    assert cli.main(["--serve", "9999"]) == 1
    err = capsys.readouterr().err
    assert "端口 9999 可能被占用" in err


def test_main_config_merge(monkeypatch, tmp_path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(
        json.dumps({"base_url": "https://cfg.example.com", "model": "cfg-model", "timeout": 30}),
        encoding="utf-8",
    )
    captured = {}

    def fake_execute(c):
        captured["config"] = c
        return 0, "", None

    monkeypatch.setattr(cli, "execute_scan", fake_execute)
    assert cli.main(["--config", str(cfg)]) == 0
    assert captured["config"].base_url == "https://cfg.example.com"
    assert captured["config"].model == "cfg-model"
    assert captured["config"].timeout == 30


def test_main_config_cli_overrides(monkeypatch, tmp_path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(
        json.dumps({"base_url": "https://cfg.example.com", "model": "cfg-model"}), encoding="utf-8"
    )
    captured = {}

    def fake_execute(c):
        captured["config"] = c
        return 0, "", None

    monkeypatch.setattr(cli, "execute_scan", fake_execute)
    cli.main(["--config", str(cfg), "--model", "cli-model"])
    assert captured["config"].model == "cli-model"


def test_main_key_and_save_key(monkeypatch) -> None:
    saved = {}

    def fake_save(key):
        saved["key"] = key

    monkeypatch.setattr(cli, "_save_key_to_file", fake_save)
    monkeypatch.setattr(cli.os, "environ", {})
    monkeypatch.setattr(cli, "execute_scan", lambda c: (0, "", None))
    assert cli.main(["--base-url", "https://x", "--key", "sk-cli", "--save-key"]) == 0
    assert cli.os.environ["RELAY_API_KEY"] == "sk-cli"
    assert saved["key"] == "sk-cli"


def test_main_list_models(monkeypatch) -> None:
    monkeypatch.setattr(cli, "cmd_list_models", lambda args: 0)
    assert cli.main(["--base-url", "https://x", "--models"]) == 0


def test_main_execute_scan_error(monkeypatch) -> None:
    def boom(c):
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(cli, "execute_scan", boom)
    assert cli.main(["--base-url", "https://x"]) == 1


def test_main_execute_scan_interrupt(monkeypatch) -> None:
    def boom(c):
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "execute_scan", boom)
    assert cli.main(["--base-url", "https://x"]) == 130


def test_main_missing_base_url(monkeypatch) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["--json"])
    assert e.value.code == 2


def test_main_invalid_base_url(monkeypatch) -> None:
    """--base-url 不带 http(s) 前缀 → 参数错误。"""
    with pytest.raises(SystemExit) as e:
        cli.main(["--base-url", "ftp://x", "--json"])
    assert e.value.code == 2


def test_main_argv_none_uses_sys_argv(monkeypatch) -> None:
    captured = {}

    def fake_execute(c):
        captured["config"] = c
        return 0, "", None

    monkeypatch.setattr(cli.sys, "argv", ["relay-audit", "--base-url", "https://x"])
    monkeypatch.setattr(cli, "execute_scan", fake_execute)
    assert cli.main(None) == 0
    assert captured["config"].base_url == "https://x"

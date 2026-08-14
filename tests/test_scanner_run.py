"""run_scan / fetch_models 编排测试 — 用 FakeClient 覆盖全部分支."""

import asyncio
import copy

import pytest

import relay_audit.scanner as scanner
from relay_audit.models import ChatResult, ScanConfig, Severity
from relay_audit.scanner import PROMPTS, fetch_models, run_scan


def _run(coro):
    return asyncio.run(coro)


def _scan(cfg):
    return _run(run_scan(cfg))


def _cr(**over) -> ChatResult:
    base = dict(
        name="",
        model_req="gpt-4o",
        ok=True,
        latency_ms=100,
        status=200,
        model_ret="gpt-4o",
        content="ok",
        usage={},
        raw_id="",
        created=0,
    )
    base.update(over)
    return ChatResult(**base)


class FakeClient:
    """可编排的 ApiClient 替身。"""

    def __init__(self, base_url, api_key, timeout=60):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.chat_calls: list[dict] = []
        self.list_models_calls = 0
        # 行为配置
        self.list_models_result = (
            200,
            [{"id": "gpt-4o"}, {"id": "claude-3"}],
            {"data": []},
            0.01,
            {},
        )
        self.ping_result = _cr(ok=True, latency_ms=50)
        self.script: dict[str, ChatResult] = {}  # content → result
        self.raise_for: dict[str, BaseException] = {}
        self.default_result = _cr()
        self.json_mode_fail = False
        self.tools_fail = False
        self.stream_result = _cr(
            name="流式响应", latency_ms=300, streaming=True, content="流式内容"
        )
        self.stream_raise: BaseException | None = None
        self.burst_results: list[ChatResult] | None = None
        self.burst_raise: BaseException | None = None
        self.stability_contents: list[str] | None = None  # 依次弹出；None 用默认

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def chat(
        self,
        model,
        messages,
        temperature=0,
        max_tokens=300,
        stream=False,
        response_format=None,
        tools=None,
        request_timeout=None,
        retry=True,
    ):
        content = messages[0]["content"] if messages else ""
        self.chat_calls.append(
            {"model": model, "content": content, "response_format": response_format, "tools": tools}
        )
        if content in self.raise_for:
            raise self.raise_for[content]
        if content == "ping":
            return self.ping_result
        if content == PROMPTS["stability"]:
            if self.stability_contents is not None:
                return _cr(content=self.stability_contents.pop(0))
            return _cr(content='{"answer":"pong"}')
        if content == PROMPTS["json_mode"]:
            if response_format and self.json_mode_fail:
                return _cr(ok=False, status=400, error="HTTP 400", content="")
            return _cr(content='{"name":"张三"}')
        if content == PROMPTS["function_calling"]:
            if tools and self.tools_fail:
                return _cr(ok=False, status=400, error="HTTP 400", content="")
            return _cr(content='{"location":"北京"}')
        if content == PROMPTS["compare"]:
            return _cr(model_req="claude-3", model_ret="claude-3", content='{"canary":"CMP-9"}')
        # 每次返回新对象——run_scan 会改写 r.name，复用同一对象会导致相互覆盖
        if content in self.script:
            return copy.copy(self.script[content])
        return copy.copy(self.default_result)

    async def chat_stream(self, model, messages, max_tokens=300, request_timeout=None):
        if self.stream_raise is not None:
            raise self.stream_raise
        return self.stream_result

    async def list_models(self):
        self.list_models_calls += 1
        return self.list_models_result

    async def concurrent_chat(self, n, model, messages, **kwargs):
        if self.burst_raise is not None:
            raise self.burst_raise
        if self.burst_results is not None:
            return self.burst_results
        return [_cr(ok=True, latency_ms=150) for _ in range(n)]


@pytest.fixture()
def fake(monkeypatch):
    f = FakeClient("https://x", "sk-test")
    monkeypatch.setattr(scanner, "ApiClient", lambda *a, **k: f)
    monkeypatch.setenv("RELAY_API_KEY", "sk-test")
    return f


def _cfg(**over) -> ScanConfig:
    base = dict(base_url="https://api.example.com", model="gpt-4o", samples=2)
    base.update(over)
    return ScanConfig(**base)


def test_run_scan_full(fake) -> None:
    fake.list_models_result = (
        200,
        [{"id": "gpt-4o"}, {"id": "claude-3"}],
        {"data": []},
        0.01,
        {"server": "nginx", "cf-ray": "ray1"},
    )
    result = _scan(_cfg(stream=True, compare=["claude-3"]))
    assert result.config.model == "gpt-4o"
    assert [m.id for m in result.models] == ["gpt-4o", "claude-3"]
    # 模型偷换检测通过（精确匹配）
    assert not any("疑似偷换" in f.title for f in result.findings)
    # 稳定性/突发/对比/流式结果存在
    names = [r.name for r in result.results]
    assert any(n.startswith("稳定性_") for n in names)
    assert any(n.startswith("突发_") for n in names)
    assert any(n.startswith("对比:") for n in names)
    assert "流式响应" in names
    assert "前置检查" in names
    # 聚合分析
    titles = [f.title for f in result.findings]
    assert "延迟统计" in titles
    assert "并发测试延迟" in titles
    assert "检测到代理/CDN 特征" in titles
    # findings 按严重度降序
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_run_scan_prefetched_ids(fake) -> None:
    result = _scan(_cfg(model_ids=["gpt-4o", "gpt-9-x"]))
    assert fake.list_models_calls == 0
    assert any("可疑" in f.title for f in result.findings)  # gpt-9-x
    assert "gpt-4o" in [m.id for m in result.models]


def test_run_scan_401(fake) -> None:
    fake.list_models_result = (401, [], {}, 0.01, {})
    result = _scan(_cfg())
    assert any(f.title == "鉴权失败" and f.severity == Severity.CRITICAL for f in result.findings)


def test_run_scan_ping_connect_error_aborts(fake) -> None:
    fake.ping_result = _cr(ok=False, status=0, error="ConnectError('boom')", content="")
    result = _scan(_cfg())
    assert any(
        f.title == "API 完全不可用" and f.severity == Severity.CRITICAL for f in result.findings
    )
    # 提前中止：只有前置检查结果
    assert [r.name for r in result.results] == ["前置检查"]


def test_run_scan_ping_timeout_continues(fake) -> None:
    fake.ping_result = _cr(ok=False, status=0, error="timeout>8s", content="")
    result = _scan(_cfg())
    assert any(
        f.title == "API 前置检查超时" and f.severity == Severity.MEDIUM for f in result.findings
    )
    assert len(result.results) > 1


def test_run_scan_ping_http_error(fake) -> None:
    fake.ping_result = _cr(ok=False, status=500, error="HTTP 500", content="")
    result = _scan(_cfg())
    assert any(
        f.title == "API 健康检查失败" and f.severity == Severity.HIGH for f in result.findings
    )
    assert len(result.results) > 1


def test_run_scan_ping_model_swap(fake) -> None:
    fake.ping_result = _cr(ok=True, model_ret="other-model")
    result = _scan(_cfg())
    assert any("模型偷换" in f.title and f.severity == Severity.HIGH for f in result.findings)


def test_run_scan_ping_retry_exhausted(fake) -> None:
    """ping 两次都抛异常 → 返回失败结果并中止扫描。"""
    fake.raise_for["ping"] = RuntimeError("conn refused")
    result = _scan(_cfg())
    assert any(f.title == "API 完全不可用" for f in result.findings)
    assert [r.name for r in result.results] == ["前置检查"]
    assert not result.results[0].ok


def test_run_scan_compare_exception(fake) -> None:
    fake.raise_for[PROMPTS["compare"]] = RuntimeError("compare boom")
    result = _scan(_cfg(compare=["claude-3"]))
    cmp = [r for r in result.results if r.name == "对比:claude-3"]
    assert cmp and not cmp[0].ok
    assert "compare boom" in cmp[0].error


def test_run_scan_json_mode_fallback(fake) -> None:
    fake.json_mode_fail = True
    result = _scan(_cfg())
    titles = [f.title for f in result.findings]
    assert any("JSON 模式 不兼容 JSON 模式" in t for t in titles)
    names = [r.name for r in result.results]
    assert "JSON 模式" in names
    assert "JSON 模式(纯文本降级)" in names


def test_run_scan_function_calling_fallback(fake) -> None:
    fake.tools_fail = True
    result = _scan(_cfg())
    titles = [f.title for f in result.findings]
    assert any("Function Calling 不兼容 Function Calling" in t for t in titles)


def test_run_scan_quick_mode(fake) -> None:
    result = _scan(_cfg(quick=True))
    names = [r.name for r in result.results]
    assert not any(n.startswith("稳定性_") for n in names)
    assert not any(n.startswith("突发_") for n in names)
    assert "JSON 模式" not in names
    assert "编码一致性" not in names
    assert "拒绝-反向Shell" not in names


def test_run_scan_skip_safety(fake) -> None:
    result = _scan(_cfg(skip_safety=True))
    names = [r.name for r in result.results]
    assert not any(n.startswith("拒绝-") for n in names)
    assert "Prompt隔离" in names


def test_run_scan_safety_tests_present(fake) -> None:
    result = _scan(_cfg())
    names = [r.name for r in result.results]
    for expected in (
        "Prompt隔离",
        "拒绝-破坏性",
        "拒绝-窃取",
        "拒绝-勒索",
        "拒绝-反向Shell",
        "拒绝-SQL注入",
    ):
        assert expected in names


def test_run_scan_task_exception(fake) -> None:
    fake.raise_for[PROMPTS["identity"]] = RuntimeError("boom")
    result = _scan(_cfg())
    assert any("测试异常中断" in f.title for f in result.findings)
    assert any(r.name == "异常" for r in result.results)


def test_run_scan_error_pattern(fake) -> None:
    fake.default_result = _cr(ok=False, status=500, error="HTTP 500", content="")
    result = _scan(_cfg(samples=1))
    assert any("大量测试返回相同错误" in f.title for f in result.findings)


def test_run_scan_stability_inconsistent(fake) -> None:
    fake.stability_contents = ['{"answer":"a"}', '{"answer":"b"}']
    result = _scan(_cfg(samples=2))
    assert any("结果不一致" in f.title for f in result.findings)


def test_run_scan_stability_exception(fake) -> None:
    fake.raise_for[PROMPTS["stability"]] = RuntimeError("stability boom")
    result = _scan(_cfg(samples=1))
    stab = [r for r in result.results if r.name == "稳定性_1"]
    assert stab and not stab[0].ok
    assert "stability boom" in stab[0].error


def test_run_scan_burst_partial_fail(fake) -> None:
    fake.burst_results = [_cr(ok=True, latency_ms=100), _cr(ok=False, status=500), _cr(ok=True)]
    result = _scan(_cfg(samples=1))
    assert any("并发测试部分失败" in f.title for f in result.findings)


def test_run_scan_burst_exception(fake) -> None:
    fake.burst_raise = RuntimeError("burst boom")
    result = _scan(_cfg(samples=1))
    burst = [r for r in result.results if r.name == "突发_1"]
    assert burst and not burst[0].ok
    assert "burst boom" in burst[0].error


def test_run_scan_stream_exception(fake) -> None:
    fake.stream_raise = RuntimeError("stream boom")
    result = _scan(_cfg(stream=True))
    sr = [r for r in result.results if r.name == "流式响应"]
    assert sr and not sr[0].ok


def test_run_scan_progress_output(fake, capsys) -> None:
    """非 quiet 模式打印实时进度行。"""
    _scan(_cfg(samples=1))
    out = capsys.readouterr().out
    assert "[OK] 基础对话 (" in out
    assert "[OK] 稳定性_1 (" in out
    assert "[OK] 突发_1 (" in out


def test_run_scan_quiet_no_progress(fake, capsys) -> None:
    """quiet 模式不打印进度。"""
    _scan(_cfg(samples=1, quiet=True))
    out = capsys.readouterr().out
    assert "[OK]" not in out


def test_run_scan_missing_key(fake, monkeypatch) -> None:
    monkeypatch.delenv("RELAY_API_KEY", raising=False)
    with pytest.raises(ValueError, match="RELAY_API_KEY"):
        _scan(_cfg())


def test_run_scan_single_sample_no_diagnostics_burst(fake) -> None:
    """samples=1 时突发测试仍以 2 路并发执行（回归 M6）。"""
    result = _scan(_cfg(samples=1))
    names = [r.name for r in result.results]
    assert "突发_1" in names and "突发_2" in names


# ── fetch_models ────────────────────────────────────────────


def test_fetch_models(fake) -> None:
    ids = _run(fetch_models("https://x", "sk-test"))
    assert ids == ["gpt-4o", "claude-3"]


def test_fetch_models_skips_non_dict(fake) -> None:
    fake.list_models_result = (200, ["gpt-4o", {"id": "claude-3"}, {"id": 42}], {}, 0.01, {})
    ids = _run(fetch_models("https://x", "sk-test"))
    assert ids == ["claude-3"]

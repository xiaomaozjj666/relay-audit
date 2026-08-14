"""Tests for relay_audit.models."""

from relay_audit._version import __version__
from relay_audit.models import (
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
)


def _result(**over) -> ChatResult:
    base = dict(
        name="t",
        model_req="gpt-4o",
        ok=True,
        latency_ms=1000,
        status=200,
        model_ret="gpt-4o",
        content="hello",
        usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        raw_id="id1",
        created=1700000000,
    )
    base.update(over)
    return ChatResult(**base)


def test_severity_values() -> None:
    assert Severity.INFO.value == "info"
    assert Severity.CRITICAL.value == "critical"
    # 定义顺序 = 严重度升序
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]


def test_finding_defaults() -> None:
    f = Finding(Severity.LOW, "标题", "详情")
    assert f.category == "general"
    assert f.reason == ""
    assert f.model_name == ""


def test_chat_result_tokens_per_second() -> None:
    r = _result(latency_ms=1000, usage={"total_tokens": 10})
    assert r.tokens_per_second == 10.0
    # 无 usage / 零延迟
    assert _result(latency_ms=0, usage={"total_tokens": 10}).tokens_per_second == 0.0
    assert _result(latency_ms=1000, usage={}).tokens_per_second == 0.0
    assert _result(latency_ms=1000, usage={"total_tokens": 0}).tokens_per_second == 0.0


def test_model_info_defaults() -> None:
    m = ModelInfo(id="gpt-4o")
    assert m.object == ""
    assert m.created == 0
    assert m.owned_by == ""


def test_scan_config_defaults() -> None:
    c = ScanConfig(base_url="https://x")
    assert c.model == ""
    assert c.timeout == 60
    assert c.samples == 1
    assert c.compare == []
    assert not c.quick
    assert not c.stream
    assert not c.skip_safety
    assert not c.json_output
    assert c.output is None
    assert not c.no_html
    assert c.config_file is None
    assert c.model_ids is None
    assert not c.quiet


def test_scan_result_counts_and_risk() -> None:
    cfg = ScanConfig(base_url="https://x")
    findings = [
        Finding(Severity.CRITICAL, "a", "d"),
        Finding(Severity.HIGH, "b", "d"),
        Finding(Severity.MEDIUM, "c", "d"),
        Finding(Severity.LOW, "d", "d"),
        Finding(Severity.INFO, "e", "d"),
    ]
    r = ScanResult(cfg, findings, [], [], "", 1.0)
    assert r.high_count == 2
    assert r.med_count == 1
    assert r.low_count == 2
    assert r.risk_level == "HIGH"

    r2 = ScanResult(cfg, [Finding(Severity.MEDIUM, "c", "d")], [], [], "", 1.0)
    assert r2.risk_level == "MEDIUM"

    r3 = ScanResult(cfg, [Finding(Severity.LOW, "d", "d")], [], [], "", 1.0)
    assert r3.risk_level == "LOW"


def test_scan_result_version_default() -> None:
    r = ScanResult(ScanConfig(base_url="https://x"), [], [], [], "", 1.0)
    assert r.version == __version__


def test_scan_result_to_dict() -> None:
    cfg = ScanConfig(base_url="https://api.example.com", model="gpt-4o")
    results = [
        _result(latency_ms=1000),
        _result(
            name="失败的",
            ok=False,
            status=500,
            error="HTTP 500 sk-abcdefghijklmnop123456",
            content="",
        ),
    ]
    findings = [
        Finding(
            Severity.HIGH, "高危", "detail sk-abc1234567890123456", "identity", model_name="gpt-4o"
        )
    ]
    r = ScanResult(
        cfg, findings, results, [ModelInfo(id="gpt-4o")], "2026-01-01T00:00:00+00:00", 12.5
    )
    d = r.to_dict()

    assert d["version"] == __version__
    assert d["base_url"] == "https://api.example.com"
    assert d["model"] == "gpt-4o"
    assert d["duration_s"] == 12.5
    assert d["risk_level"] == "HIGH"
    assert d["summary"] == {
        "high": 1,
        "medium": 0,
        "low": 0,
        "total": 1,
        "tests": 2,
    }
    # 脱敏
    assert "sk-abc123" not in d["findings"][0]["detail"]
    assert "[REDACTED]" in d["findings"][0]["detail"]
    assert d["findings"][0]["severity"] == "high"
    assert d["findings"][0]["category"] == "identity"
    assert d["findings"][0]["model_name"] == "gpt-4o"

    t = d["tests"][0]
    assert t["name"] == "t"
    assert t["ok"] is True
    assert t["status"] == 200
    assert t["latency_ms"] == 1000
    assert t["model_req"] == "gpt-4o"
    assert t["model_ret"] == "gpt-4o"
    assert t["tokens_per_second"] == 10.0
    assert t["streaming"] is False
    assert t["turn_count"] == 1
    assert t["error"] is None

    # 失败测试携带脱敏后的 error
    t2 = d["tests"][1]
    assert t2["ok"] is False
    assert "sk-abcdefghijklmnop123456" not in t2["error"]
    assert "[REDACTED]" in t2["error"]

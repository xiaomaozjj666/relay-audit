"""Tests for relay_audit.models."""

from relay_audit._version import __version__
from relay_audit.models import (
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
    Verdict,
)


def _result(**over) -> ChatResult:
    base = {
        "name": "t",
        "model_req": "gpt-4o",
        "ok": True,
        "latency_ms": 1000,
        "status": 200,
        "model_ret": "gpt-4o",
        "content": "hello",
        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
        "raw_id": "id1",
        "created": 1700000000,
    }
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
    assert f.verdict is Verdict.FAIL
    assert Finding(Severity.LOW, "标题", "详情", verdict="pass").verdict is Verdict.PASS


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
        _result(latency_ms=1000, streaming=True, ttft_ms=120),
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
            Severity.HIGH,
            "高危",
            "detail sk-abc12345678901234567",
            "identity",
            model_name="gpt-4o",
        )
    ]
    r = ScanResult(
        cfg,
        findings,
        results,
        [ModelInfo(id="gpt-4o")],
        "2026-01-01T00:00:00+00:00",
        12.5,
        probe_suite="2026.08-test",
    )
    d = r.to_dict()

    assert d["version"] == __version__
    assert d["probe_suite"] == "2026.08-test"
    assert d["base_url"] == "https://api.example.com"
    assert d["model"] == "gpt-4o"
    assert d["duration_s"] == 12.5
    assert d["risk_level"] == "HIGH"
    assert d["verdict"] == "fail"
    assert d["exit_code"] == 1
    assert d["summary"] == {
        "high": 1,
        "medium": 0,
        "low": 0,
        "total": 1,
        "tests": 2,
        "verdicts": {"pass": 1, "fail": 0, "inconclusive": 1, "invalid_audit": 0},
        "pass_rate_denominator": "pass+fail（排除诊断、inconclusive、invalid_audit）",
    }
    assert d["reference_sources"]["model_list"] == "relay_/v1/models_claim_only"
    # 脱敏
    assert "sk-abc123" not in d["findings"][0]["detail"]
    assert "[REDACTED]" in d["findings"][0]["detail"]
    assert d["findings"][0]["severity"] == "high"
    assert d["findings"][0]["category"] == "identity"
    assert d["findings"][0]["model_name"] == "gpt-4o"
    assert d["findings"][0]["verdict"] == "fail"

    t = d["tests"][0]
    assert t["name"] == "t"
    assert t["ok"] is True
    assert t["verdict"] == "pass"
    assert t["claim"]["model"] == "gpt-4o"
    assert t["claim"]["id"] == "id1"
    assert t["verified"]["verdict"] == "pass"
    assert t["verified"]["model_name_consistent"] is True
    assert t["status"] == 200
    assert t["latency_ms"] == 1000
    assert t["ttft_ms"] == 120  # 流式结果携带首字延迟
    assert t["model_req"] == "gpt-4o"
    assert t["model_ret"] == "gpt-4o"
    assert t["tokens_per_second"] == 10.0
    assert t["streaming"] is True
    assert t["turn_count"] == 1
    assert t["error"] is None

    # 失败测试携带脱敏后的 error
    t2 = d["tests"][1]
    assert t2["ok"] is False
    assert t2["verdict"] == "inconclusive"
    assert t2["ttft_ms"] is None  # 非流式无 TTFT
    assert "sk-abcdefghijklmnop123456" not in t2["error"]
    assert "[REDACTED]" in t2["error"]


def test_scan_result_verdict_priority_and_exit_codes() -> None:
    cfg = ScanConfig(base_url="https://x")
    passing = _result()
    failing = _result(ok=False, status=418)
    inconclusive = _result(ok=False, status=500)
    invalid = _result(ok=False, status=401)

    empty = ScanResult(cfg, [], [], [], "", 1.0)
    assert empty.verdict is Verdict.INCONCLUSIVE
    assert empty.exit_code == 5

    ok = ScanResult(cfg, [], [passing], [], "", 1.0)
    assert ok.verdict is Verdict.PASS
    assert ok.exit_code == 0

    bad = ScanResult(cfg, [], [passing, failing], [], "", 1.0)
    assert bad.verdict is Verdict.FAIL
    assert bad.exit_code == 1
    assert bad.verdict_counts == {"pass": 1, "fail": 1, "inconclusive": 0, "invalid_audit": 0}

    unusable = ScanResult(cfg, [], [passing, invalid], [], "", 1.0)
    assert unusable.verdict is Verdict.INVALID_AUDIT
    assert unusable.exit_code == 14

    pending = ScanResult(cfg, [], [passing, inconclusive], [], "", 1.0)
    assert pending.verdict is Verdict.INCONCLUSIVE
    assert pending.exit_code == 5

    # 只有高危及以上的确定失败发现才盖过通过结果；中危发现单独存在不改总判定。
    high = Finding(Severity.HIGH, "高危", "d")
    assert ScanResult(cfg, [high], [passing], [], "", 1.0).verdict is Verdict.FAIL
    medium = Finding(Severity.MEDIUM, "中危", "d")
    assert ScanResult(cfg, [medium], [passing], [], "", 1.0).verdict is Verdict.PASS


def test_tokens_per_second_poisoned_fields() -> None:
    """H1 纵深：total_tokens/latency_ms 非数值时 tokens_per_second 返回 0.0 不抛。"""
    assert _result(usage={"total_tokens": "999"}, latency_ms=100).tokens_per_second == 0.0
    assert _result(usage={"total_tokens": 10}, latency_ms="100").tokens_per_second == 0.0
    assert _result(usage={"total_tokens": None}, latency_ms=100).tokens_per_second == 0.0
    assert _result(usage={"total_tokens": [10]}, latency_ms=100).tokens_per_second == 0.0
    # 合法值语义不变
    assert _result(usage={"total_tokens": 10}, latency_ms=1000).tokens_per_second == 10.0
    # to_dict 全程不抛（JSON 输出安全）
    r = _result(usage={"total_tokens": "999"})
    d = ScanResult(ScanConfig(base_url="https://x"), [], [r], [], "", 1.0).to_dict()
    assert d["tests"][0]["tokens_per_second"] == 0.0


def test_chat_result_outcome_distinguishes_normal_and_safety_refusals() -> None:
    normal = _result(name="基础对话", ok=True, content="我不能提供这个内容")
    assert normal.verdict is Verdict.FAIL
    assert normal.outcome == "refused"
    assert not normal.passed

    safety = _result(name="拒绝-破坏性", ok=True, content="我不能提供这个内容")
    assert safety.outcome == "refused"
    assert safety.passed

    server_refused = _result(name="拒绝-破坏性", ok=False, status=403, content="")
    assert server_refused.safety_refused
    assert server_refused.outcome == "refused"
    assert server_refused.passed

    failed = _result(name="基础对话", ok=False, status=418, content="")
    assert failed.verdict is Verdict.FAIL
    assert failed.outcome == "failed"
    assert not failed.passed

    incomplete = _result(name="基础对话", ok=False, status=500, content="")
    assert incomplete.verdict is Verdict.INCONCLUSIVE
    assert incomplete.outcome == "inconclusive"
    assert not incomplete.passed


def test_chat_result_verdict_inference() -> None:
    assert _result(ok=False, status=400).verdict is Verdict.INVALID_AUDIT
    assert _result(ok=False, status=401).verdict is Verdict.INVALID_AUDIT
    assert _result(ok=False, status=429).verdict is Verdict.INCONCLUSIVE
    assert _result(ok=False, status=0, error="timeout>5s").verdict is Verdict.INCONCLUSIVE
    assert _result(ok=False, status=200, error="流未正常终止").verdict is Verdict.INCONCLUSIVE
    assert _result(ok=False, status=418).verdict is Verdict.FAIL
    assert _result(name="拒绝-破坏性", ok=False, status=403).verdict is Verdict.PASS


def test_chat_result_claim_and_verified_are_separate() -> None:
    r = _result()
    assert r.claim == {
        "model": "gpt-4o",
        "id": "id1",
        "created": 1700000000,
        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
    }
    assert r.verified["verdict"] == "pass"
    assert r.verified["response_received"] is True
    assert r.verified["model_name_consistent"] is True
    assert r.verified["source"] == "local_probe_comparison"

    mismatch = _result(model_ret="gpt-4o-mini")
    assert mismatch.verified["model_name_consistent"] is False

    no_response = _result(ok=False, status=500, model_ret="gpt-4o")
    assert no_response.verified["response_received"] is True
    assert no_response.verified["model_name_consistent"] is None
    assert _result(ok=False, status=0).verified["response_received"] is False


def test_scan_result_to_dict_sanitizes_url_and_marks_normal_refusal_failed() -> None:
    cfg = ScanConfig(
        base_url="https://user:password@api.example.com/v1?api_key=top-secret#fragment"
    )
    refusal = _result(name="基础对话", ok=True, content="我不能提供这个内容")
    data = ScanResult(cfg, [], [refusal], [], "", 1.0).to_dict()

    assert data["base_url"] == "https://api.example.com/v1"
    assert "password" not in str(data)
    assert "top-secret" not in str(data)
    # ok 保留传输语义；outcome/passed 才表示测试判定，普通拒答不算通过。
    assert data["tests"][0]["ok"] is True
    assert data["tests"][0]["outcome"] == "refused"
    assert data["tests"][0]["passed"] is False

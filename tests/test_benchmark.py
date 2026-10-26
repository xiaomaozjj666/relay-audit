"""Tests for relay_audit.benchmark — 快照归一化、纵向比较与 CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from relay_audit import benchmark
from relay_audit.models import ChatResult, Finding, ScanConfig, ScanResult, Severity


def _test(name: str, ok: bool, latency: int = 100, model: str = "gpt-4o", status: int = 200):
    return {
        "name": name,
        "ok": ok,
        "status": status,
        "latency_ms": latency,
        "model_ret": model,
    }


def _scan(
    tests: list[dict],
    *,
    model: str = "gpt-4o",
    suite: str = "2026.08.4",
    risk: str | None = None,
    findings: list[dict] | None = None,
    base_url: str = "https://relay.example.com",
) -> dict:
    findings = findings or []
    if risk is None:
        if any(item["severity"] in {"high", "critical"} for item in findings):
            risk = "HIGH"
        elif any(item["severity"] == "medium" for item in findings):
            risk = "MEDIUM"
        else:
            risk = "LOW"
    return {
        "version": "2.3.8",
        "probe_suite": suite,
        "base_url": base_url,
        "model": model,
        "risk_level": risk,
        "summary": {
            "high": sum(1 for item in findings if item["severity"] in {"high", "critical"}),
            "medium": sum(1 for item in findings if item["severity"] == "medium"),
            "low": 0,
            "total": len(findings),
            "tests": len(tests),
        },
        "findings": findings,
        "tests": tests,
    }


def _write(tmp_path: Path, name: str, payload: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def _snapshot(payload: dict, captured_at: str = "2026-10-01T10:00:00+08:00") -> dict:
    return benchmark.snapshot_from_payload(payload, captured_at=captured_at)


# ── 快照归一化 ──────────────────────────────────────────────


def test_snapshot_normalizes_full_scan() -> None:
    payload = _scan(
        [_test("基础对话", True), _test("模型身份", False, 800, "gpt-3.5-turbo")],
        findings=[{"severity": "high", "category": "identity", "title": "模型偷换"}],
    )
    snap = _snapshot(payload)
    assert snap["snapshot_version"] == benchmark.SNAPSHOT_VERSION
    assert snap["probe_suite"] == "2026.08.4"
    assert snap["risk_level"] == "HIGH"
    assert snap["observed_models"] == ["gpt-3.5-turbo", "gpt-4o"]
    assert snap["summary"] == {"high": 1, "medium": 0, "findings": 1, "tests": 2, "passed": 1}
    assert snap["findings"][0]["title"] == "模型偷换"


def test_snapshot_accepts_persisted_scan_schema() -> None:
    payload = {
        "timestamp": "20261001_100000",
        "base_url": "https://relay.example.com",
        "probe_suite": "2026.08.4",
        "summary": {
            "risk_level": "MEDIUM",
            "high_count": 0,
            "total_findings": 1,
            "tests_passed": 1,
            "tests_total": 2,
        },
        "findings": [{"severity": "medium", "category": "quality", "title": "乱码"}],
        "results": [
            {"name": "基础对话", "ok": True, "latency_ms": 120, "status": 200},
            {"name": "长上下文", "ok": False, "latency_ms": 900, "status": 500},
        ],
    }
    snap = _snapshot(payload)
    assert snap["risk_level"] == "MEDIUM"
    assert snap["model"] == ""
    assert snap["summary"]["high"] == 0
    assert snap["summary"]["medium"] == 1
    assert snap["summary"]["passed"] == 1


def test_snapshot_infers_risk_and_merges_duplicate_tests() -> None:
    payload = {
        "tests": [
            _test("稳定性", True, 100),
            _test("稳定性", False, 300),
            {"name": "稳定性", "ok": True, "status": 0, "latency_ms": 200},
        ],
        "findings": [{"severity": "medium", "title": "抖动"}],
    }
    snap = _snapshot(payload)
    assert snap["risk_level"] == "MEDIUM"
    observations = snap["observations"]
    assert len(observations) == 1
    assert observations[0]["ok"] is False
    assert observations[0]["latency_ms"] == 300
    assert observations[0]["status"] == 200


@pytest.mark.parametrize(
    "payload,message",
    [
        ([], "顶层"),
        ({"tests": []}, "非空"),
        ({"results": "nope"}, "非空"),
        ({"tests": [{"ok": True}]}, "缺少 name"),
        ({"tests": [{"name": "x", "ok": "yes"}]}, "布尔"),
        ({"tests": ["x"]}, "不是 JSON 对象"),
    ],
)
def test_snapshot_rejects_bad_payloads(payload: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        benchmark.snapshot_from_payload(payload)  # type: ignore[arg-type]


def test_snapshot_guards_non_finite_and_negative_numbers() -> None:
    payload = {
        "tests": [
            {
                "name": "x",
                "ok": True,
                "status": float("inf"),
                "latency_ms": float("nan"),
            }
        ],
        "summary": {"high": -3, "medium": float("inf")},
    }
    snap = _snapshot(payload)
    observation = snap["observations"][0]
    assert observation["status"] == 0
    assert observation["latency_ms"] == 0
    assert snap["summary"]["high"] == 0
    assert snap["summary"]["medium"] == 0


def test_load_scan_records_source_and_hash(tmp_path: Path) -> None:
    path = _write(tmp_path, "scan.json", _scan([_test("基础对话", True)]))
    snap = benchmark.load_scan(path)
    assert snap["source"] == "scan.json"
    assert len(snap["source_sha256"]) == 64


# ── 快照读写与校验 ──────────────────────────────────────────


def test_save_load_and_validate_snapshot(tmp_path: Path) -> None:
    snap = _snapshot(_scan([_test("基础对话", True)]))
    path = benchmark.save_snapshot(snap, tmp_path)
    assert path.is_file()
    loaded = benchmark.load_snapshot(path)
    assert loaded["observations"][0]["name"] == "基础对话"
    assert benchmark.load_scan(path)["snapshot_version"] == benchmark.SNAPSHOT_VERSION

    raw = benchmark.load_snapshot(_write(tmp_path, "raw.json", _scan([_test("x", True)])))
    assert raw["snapshot_version"] == benchmark.SNAPSHOT_VERSION


@pytest.mark.parametrize(
    "payload,message",
    [
        ({"snapshot_version": 99, "observations": [{"name": "x"}]}, "版本"),
        ({"snapshot_version": 1, "observations": []}, "observations"),
        (
            {
                "snapshot_version": 1,
                "observations": [{"name": "x", "ok": True}, {"name": "x", "ok": True}],
            },
            "重复",
        ),
        ({"snapshot_version": 1, "observations": [{"ok": True}]}, "缺少 name"),
        ({"snapshot_version": 1, "observations": [{"name": "x", "ok": "no"}]}, "布尔"),
        (
            {"snapshot_version": 1, "observations": [{"name": "x", "ok": True, "latency_ms": -1}]},
            "非负整数",
        ),
    ],
)
def test_validate_snapshot_rejects(tmp_path: Path, payload: dict, message: str) -> None:
    path = _write(tmp_path, "bad.json", payload)
    with pytest.raises(ValueError, match=message):
        benchmark.load_snapshot(path)


def test_capture_result_from_scan_result(tmp_path: Path) -> None:
    result = ScanResult(
        config=ScanConfig(base_url="https://x", model="m"),
        findings=[Finding(Severity.HIGH, "高危", "d", "identity")],
        results=[
            ChatResult(
                name="基础对话",
                model_req="m",
                ok=True,
                latency_ms=100,
                status=200,
                model_ret="m",
                content="ok",
                usage={},
                raw_id="",
                created=0,
            )
        ],
        models=[],
        started_at="2026-10-01T00:00:00+00:00",
        duration_s=1.0,
        probe_suite="2026.08.4",
    )
    path = benchmark.capture_result(result, tmp_path)
    snap = json.loads(path.read_text(encoding="utf-8"))
    assert snap["risk_level"] == "HIGH"
    assert snap["tool_version"] == result.version
    assert snap["observations"][0]["model_ret"] == "m"


# ── McNemar 与比较结论 ─────────────────────────────────────


def test_mcnemar_exact() -> None:
    assert benchmark.mcnemar_exact(0, 0) == 1.0
    assert benchmark.mcnemar_exact(0, 6) == pytest.approx(0.03125)
    assert benchmark.mcnemar_exact(6, 0) == pytest.approx(0.03125)
    assert benchmark.mcnemar_exact(1, 1) == 1.0
    with pytest.raises(ValueError):
        benchmark.mcnemar_exact(-1, 0)


def test_compare_stable() -> None:
    tests = [_test(name, True) for name in ("a", "b", "c")]
    result = benchmark.compare_snapshots(_snapshot(_scan(tests)), _snapshot(_scan(tests)))
    assert result["verdict"] == "stable"
    assert result["comparable"] is True
    assert result["transitions"]["stable_pass"] == 3
    assert result["mcnemar_p"] == 1.0


def test_compare_improved() -> None:
    baseline = [_test(f"t{i}", False) for i in range(6)]
    candidate = [_test(f"t{i}", True) for i in range(6)]
    result = benchmark.compare_snapshots(_snapshot(_scan(baseline)), _snapshot(_scan(candidate)))
    assert result["verdict"] == "improved"
    assert len(result["transitions"]["improved"]) == 6
    assert result["mcnemar_p"] == pytest.approx(0.03125)


def test_compare_regressed() -> None:
    baseline = [_test(f"t{i}", True) for i in range(6)]
    candidate = [_test(f"t{i}", False) for i in range(6)]
    result = benchmark.compare_snapshots(_snapshot(_scan(baseline)), _snapshot(_scan(candidate)))
    assert result["verdict"] == "regressed"
    assert len(result["transitions"]["regressed"]) == 6
    assert any("由通过转为失败" in note for note in result["notes"])


def test_compare_changed_but_not_significant() -> None:
    baseline = [_test("a", True), _test("b", True)]
    candidate = [_test("a", False), _test("b", True)]
    result = benchmark.compare_snapshots(_snapshot(_scan(baseline)), _snapshot(_scan(candidate)))
    assert result["verdict"] == "changed"
    assert result["mcnemar_p"] == 1.0
    assert any("未达显著" in note for note in result["notes"])


def test_compare_risk_regression_without_test_flips() -> None:
    tests = [_test("a", True)]
    baseline = _scan(tests)
    candidate = _scan(
        tests,
        risk="HIGH",
        findings=[{"severity": "high", "category": "identity", "title": "模型偷换"}],
    )
    result = benchmark.compare_snapshots(_snapshot(baseline), _snapshot(candidate))
    assert result["verdict"] == "regressed"
    assert result["risk"]["regressed"] is True
    assert result["notes"]


def test_risk_regression_does_not_call_flips_noise() -> None:
    baseline = _scan([_test(f"t{i}", True) for i in range(4)])
    candidate = _scan(
        [_test(f"t{i}", False) for i in range(4)],
        risk="HIGH",
        findings=[{"severity": "high", "category": "identity", "title": "模型偷换"}],
    )
    result = benchmark.compare_snapshots(_snapshot(baseline), _snapshot(candidate))
    assert result["verdict"] == "regressed"
    assert not any("抖动" in note for note in result["notes"])


def test_compare_model_drift_and_latency() -> None:
    baseline = [_test(f"t{i}", True, 100, "gpt-4o") for i in range(3)]
    candidate = [_test(f"t{i}", True, 300, "gpt-3.5-turbo") for i in range(3)]
    result = benchmark.compare_snapshots(_snapshot(_scan(baseline)), _snapshot(_scan(candidate)))
    assert result["verdict"] == "changed"
    assert result["model_drift"]["changed"] is True
    assert result["model_drift"]["per_test_total"] == 3
    assert result["latency"]["samples"] == 3
    assert result["latency"]["change_pct"] == pytest.approx(200.0)
    assert result["latency"]["regressed"] is True


@pytest.mark.parametrize(
    "baseline,candidate,message",
    [
        (_scan([_test("a", True)]), _scan([_test("a", True)], model="other"), "请求模型"),
        (
            _scan([_test("a", True)]),
            _scan([_test("a", True)], base_url="https://other.example.com"),
            "base_url",
        ),
        (
            _scan([_test("a", True)]),
            _scan([_test("a", True)], suite="2026.09.1"),
            "探针套件",
        ),
        (_scan([_test("a", True)]), _scan([_test("b", True)]), "没有共同探针"),
    ],
)
def test_compare_incomparable(baseline: dict, candidate: dict, message: str) -> None:
    result = benchmark.compare_snapshots(_snapshot(baseline), _snapshot(candidate))
    assert result["verdict"] == "incomparable"
    assert result["comparable"] is False
    assert any(message in reason for reason in result["reasons"])


def test_compare_low_overlap_is_incomparable() -> None:
    baseline = [_test("a", True), _test("b", True), _test("c", True)]
    candidate = [_test("a", True), _test("d", True), _test("e", True)]
    result = benchmark.compare_snapshots(_snapshot(_scan(baseline)), _snapshot(_scan(candidate)))
    assert result["verdict"] == "incomparable"
    assert result["transitions"]["added"] == ["d", "e"]
    assert result["transitions"]["removed"] == ["b", "c"]


# ── 历史 ────────────────────────────────────────────────────


def test_history_orders_and_skips_invalid(tmp_path: Path) -> None:
    benchmark.save_snapshot(_snapshot(_scan([_test("a", True)]), "2026-10-02T00:00:00"), tmp_path)
    benchmark.save_snapshot(_snapshot(_scan([_test("a", False)]), "2026-10-01T00:00:00"), tmp_path)
    (tmp_path / "broken.json").write_text("not-json", encoding="utf-8")
    (tmp_path / "other.json").write_text('{"snapshot_version": 99}', encoding="utf-8")

    history = benchmark.load_history(tmp_path)
    assert [item["captured_at"][:10] for item in history] == ["2026-10-01", "2026-10-02"]
    text = benchmark.render_history(history)
    assert "2026-10-01" in text and "通过" in text


def test_render_history_marks_context_breaks(tmp_path: Path) -> None:
    high = [{"severity": "high", "category": "identity", "title": "模型偷换"}]
    first = _snapshot(_scan([_test("a", True)]), "2026-10-01T00:00:00")
    worse = _snapshot(
        _scan([_test("a", True)], findings=high),
        "2026-10-02T00:00:00",
    )
    other = _snapshot(
        _scan([_test("a", True)], base_url="https://other.example.com"),
        "2026-10-03T00:00:00",
    )
    switched = _snapshot(
        _scan([_test("a", True)], base_url="https://other.example.com", model="gpt-4o-mini"),
        "2026-10-04T00:00:00",
    )

    text = benchmark.render_history([first, worse, other, switched])
    assert "端点" in text
    assert "relay.example.com" in text and "other.example.com" in text
    assert "↑" in text
    assert "↓" not in text
    assert "已跳过风险箭头" in text


def test_render_history_empty() -> None:
    assert benchmark.render_history([]) == "没有可用的快照。"


def _trend_snapshot(
    captured_at: str,
    *,
    risk: str = "LOW",
    ok: bool = True,
    base_url: str = "https://relay.example.com",
    model: str = "gpt-4o",
) -> dict:
    findings = []
    if risk != "LOW":
        findings = [{"severity": risk.lower(), "category": "quality", "title": "趋势故障"}]
    return _snapshot(
        _scan(
            [_test(f"t{i}", ok) for i in range(6)],
            risk=risk,
            findings=findings,
            base_url=base_url,
            model=model,
        ),
        captured_at,
    )


def test_trends_require_three_snapshots_before_alerting() -> None:
    result = benchmark.analyze_history(
        [
            _trend_snapshot("2026-10-01T00:00:00Z"),
            _trend_snapshot("2026-10-02T00:00:00Z", risk="HIGH"),
        ]
    )
    assert result["groups"][0]["status"] == "insufficient_data"
    assert result["groups"][0]["alert"] is False
    assert result["groups"][0]["trend"] is None


def test_trends_ignore_non_significant_noise() -> None:
    snapshots = [
        _trend_snapshot("2026-10-01T00:00:00Z"),
        _trend_snapshot("2026-10-02T00:00:00Z"),
        _trend_snapshot("2026-10-03T00:00:00Z"),
    ]
    snapshots[1]["observations"][0]["ok"] = False
    snapshots[2]["observations"][0]["ok"] = False
    snapshots[2]["observations"][1]["ok"] = False
    group = benchmark.analyze_history(snapshots)["groups"][0]
    assert group["status"] == "changed"
    assert group["alert"] is False


def test_trends_alert_only_for_active_regression() -> None:
    active = benchmark.analyze_history(
        [
            _trend_snapshot("2026-10-01T00:00:00Z"),
            _trend_snapshot("2026-10-02T00:00:00Z"),
            _trend_snapshot("2026-10-03T00:00:00Z", risk="HIGH"),
        ]
    )
    recovered = benchmark.analyze_history(
        [
            _trend_snapshot("2026-10-01T00:00:00Z"),
            _trend_snapshot("2026-10-02T00:00:00Z", risk="MEDIUM"),
            _trend_snapshot("2026-10-03T00:00:00Z", risk="HIGH"),
            _trend_snapshot("2026-10-04T00:00:00Z"),
        ]
    )
    assert active["alert_count"] == 1
    assert active["groups"][0]["trend"]["alert_reasons"] == ["latest_regression"]
    assert recovered["alert_count"] == 0
    assert recovered["groups"][0]["trend"]["max_consecutive_regressions"] == 2


def test_trends_isolate_endpoint_and_model_groups() -> None:
    snapshots = [_trend_snapshot(f"2026-10-0{i}T00:00:00Z") for i in range(1, 4)]
    snapshots.append(
        _trend_snapshot("2026-10-03T00:00:00Z", risk="HIGH", base_url="https://other.example.com")
    )
    snapshots.append(_trend_snapshot("2026-10-03T00:00:00Z", risk="HIGH", model="other-model"))
    result = benchmark.analyze_history(snapshots)
    assert result["group_count"] == 3
    assert result["alert_count"] == 0
    assert sum(group["status"] == "insufficient_data" for group in result["groups"]) == 2


def test_trends_sort_timestamps_and_same_instant_deterministically() -> None:
    snapshots = [
        _trend_snapshot("2026-10-03T00:00:00Z", risk="HIGH"),
        _trend_snapshot("2026-10-01T08:00:00+08:00"),
        _trend_snapshot("2026-10-02T00:00:00"),
    ]
    forward = benchmark.analyze_history(snapshots)
    reverse = benchmark.analyze_history(list(reversed(snapshots)))
    assert forward == reverse
    assert forward["groups"][0]["status"] == "regressed"
    assert [item["candidate"]["captured_at"] for item in forward["groups"][0]["comparisons"]] == [
        "2026-10-02T00:00:00",
        "2026-10-03T00:00:00Z",
    ]


# ── CLI ─────────────────────────────────────────────────────


def test_cli_capture_compare_and_history(tmp_path: Path, capsys) -> None:
    source = tmp_path / "scans"
    source.mkdir()
    _write(source, "a.json", _scan([_test("a", True), _test("b", True)]))
    _write(source, "b.json", _scan([_test("a", False), _test("b", False)]))
    out = tmp_path / "snaps"

    assert benchmark.main(["capture", str(source), "--out", str(out)]) == 0
    assert len(list(out.glob("*.json"))) == 2

    first, second = sorted(out.glob("*.json"))
    assert benchmark.main(["compare", str(first), str(second)]) == 0
    captured = capsys.readouterr().out
    assert "有变化" in captured

    assert benchmark.main(["history", str(out)]) == 0
    assert "模型" in capsys.readouterr().out


def test_cli_compare_exit_codes_and_markdown(tmp_path: Path, capsys) -> None:
    passed = _write(tmp_path, "passed.json", _scan([_test(f"t{i}", True) for i in range(6)]))
    failed = _write(tmp_path, "failed.json", _scan([_test(f"t{i}", False) for i in range(6)]))
    markdown = tmp_path / "report.md"

    assert benchmark.main(["compare", str(failed), str(passed)]) == 0
    assert "改善" in capsys.readouterr().out
    assert benchmark.main(["compare", str(passed), str(failed)]) == 1
    assert "回归" in capsys.readouterr().out
    assert (
        benchmark.main(["compare", str(passed), str(failed), "--json", "--markdown", str(markdown)])
        == 1
    )
    assert json.loads(capsys.readouterr().out)["verdict"] == "regressed"
    assert "纵向基准报告" in markdown.read_text(encoding="utf-8")


def test_cli_trends_json_and_alert_exit_code(tmp_path: Path, capsys) -> None:
    for index, risk in enumerate(("LOW", "LOW", "HIGH"), start=1):
        snapshot = _trend_snapshot(f"2026-10-0{index}T00:00:00Z", risk=risk)
        (tmp_path / f"{index}.json").write_text(json.dumps(snapshot), encoding="utf-8")

    assert benchmark.main(["trends", str(tmp_path), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["alert_count"] == 1
    assert payload["groups"][0]["snapshot_count"] == 3
    assert benchmark.main(["trends", str(tmp_path)]) == 1
    assert "latest_regression" in capsys.readouterr().out


def test_cli_errors(tmp_path: Path, capsys) -> None:
    assert benchmark.main(["capture", str(tmp_path / "missing")]) == 2
    assert "不存在" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("not-json", encoding="utf-8")
    assert benchmark.main(["capture", str(bad)]) == 2
    assert "失败" in capsys.readouterr().err

    empty = tmp_path / "empty"
    empty.mkdir()
    assert benchmark.main(["capture", str(empty)]) == 2
    assert "没有 JSON" in capsys.readouterr().err

    assert benchmark.main(["history", str(tmp_path / "missing-dir")]) == 2
    assert "快照目录不存在" in capsys.readouterr().err


def test_main_cli_snapshot_flag(tmp_path: Path, monkeypatch, capsys) -> None:
    from relay_audit import cli

    result = ScanResult(
        config=ScanConfig(base_url="https://x", model="m"),
        findings=[],
        results=[
            ChatResult(
                name="基础对话",
                model_req="m",
                ok=True,
                latency_ms=100,
                status=200,
                model_ret="m",
                content="ok",
                usage={},
                raw_id="",
                created=0,
            )
        ],
        models=[],
        started_at="2026-10-01T00:00:00+00:00",
        duration_s=1.0,
        probe_suite="2026.08.4",
    )
    monkeypatch.setattr(cli, "execute_scan", lambda cfg: (0, "", result))
    assert (
        cli.main(["--base-url", "https://x", "--snapshot", "--benchmark-dir", str(tmp_path)]) == 0
    )
    assert len(list(tmp_path.glob("*.json"))) == 1
    assert "快照" in capsys.readouterr().out


def test_main_cli_snapshot_failure_keeps_exit_code(tmp_path: Path, monkeypatch, capsys) -> None:
    from relay_audit import cli

    monkeypatch.setattr(cli, "execute_scan", lambda cfg: (0, "", object()))
    assert (
        cli.main(["--base-url", "https://x", "--snapshot", "--benchmark-dir", str(tmp_path)]) == 0
    )
    assert "快照写入失败" in capsys.readouterr().err

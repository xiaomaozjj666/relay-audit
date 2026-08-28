"""Tests for relay_audit.calibrate — 校准工具全分支覆盖."""

import json
from pathlib import Path

import pytest

import relay_audit.calibrate as calibrate
from relay_audit.models import Finding, ScanConfig, ScanResult, Severity


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def _result(high: int = 0, med: int = 0) -> ScanResult:
    findings = [Finding(Severity.HIGH, f"高危{i}", "d", "identity") for i in range(high)]
    findings += [Finding(Severity.MEDIUM, f"中危{i}", "d", "quality") for i in range(med)]
    return ScanResult(
        config=ScanConfig(base_url="https://x", model="m"),
        findings=findings,
        results=[],
        models=[],
        started_at="2026-08-29T00:00:00+00:00",
        duration_s=1.0,
        probe_suite="2026.08.1",
    )


def _targets_file(tmp_path: Path, items: list[dict]) -> str:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
    return str(path)


def _valid_item(**over) -> dict:
    base = {"name": "站A", "base_url": "https://a.example.com", "api_key": "sk-a", "label": "high"}
    base.update(over)
    return base


# ── load_targets ────────────────────────────────────────────


def test_load_targets_ok(tmp_path) -> None:
    path = _targets_file(
        tmp_path,
        [_valid_item(note="已知偷换", model="gpt-4o"), _valid_item(name="干净站", label="no_high")],
    )
    targets = calibrate.load_targets(path)
    assert len(targets) == 2
    assert targets[0].note == "已知偷换"
    assert targets[0].model == "gpt-4o"
    assert targets[1].label == "no_high"
    assert targets[1].model == ""  # 可选字段默认空


def test_load_targets_rejects(tmp_path) -> None:
    cases = [
        ([], "非空"),
        ({"a": 1}, "数组"),
        ([_valid_item(), "not-dict"], "JSON 对象"),
        ([{"name": "x", "base_url": "u", "label": "high"}], "缺少必填字段"),
        ([_valid_item(label="clean")], "label 必须是"),
    ]
    for items, msg in cases:
        path = tmp_path / "t.json"
        path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
        with pytest.raises(ValueError, match=msg):
            calibrate.load_targets(str(path))


def test_load_targets_missing_file(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        calibrate.load_targets(str(tmp_path / "nope.json"))


# ── flagged / evaluate ──────────────────────────────────────


def test_flagged() -> None:
    assert calibrate.flagged(_result(high=1))
    assert not calibrate.flagged(_result())


def test_evaluate_perfect() -> None:
    rows = [
        (_t("a", "high"), _result(high=1)),
        (_t("b", "no_high"), _result()),
    ]
    s = calibrate.evaluate(rows)
    assert (s["tp"], s["fn"], s["tn"], s["fp"], s["failures"]) == (1, 0, 1, 0, 0)
    assert s["precision"] == 1.0 and s["recall"] == 1.0


def _t(name: str, label: str) -> calibrate.CalibrationTarget:
    return calibrate.CalibrationTarget(name=name, base_url="https://x", api_key="sk-x", label=label)


def test_evaluate_fp_and_fn() -> None:
    rows = [
        (_t("a", "high"), _result()),  # 漏报
        (_t("b", "no_high"), _result(high=1)),  # 误报
    ]
    s = calibrate.evaluate(rows)
    assert (s["tp"], s["fn"], s["tn"], s["fp"]) == (0, 1, 0, 1)
    assert s["precision"] == 0.0 and s["recall"] == 0.0


def test_evaluate_no_predicted_positives() -> None:
    s = calibrate.evaluate([(_t("b", "no_high"), _result())])
    assert s["precision"] is None and s["recall"] is None


def test_evaluate_scan_failures_excluded() -> None:
    rows = [(_t("a", "high"), None), (_t("b", "high"), _result(high=1))]
    s = calibrate.evaluate(rows)
    assert s["failures"] == 1 and s["total"] == 2 and s["tp"] == 1


# ── scan_all ────────────────────────────────────────────────


def test_scan_all_sequential_env(monkeypatch) -> None:
    seen_keys = []

    async def fake_run(config):
        import os

        seen_keys.append(os.environ["RELAY_API_KEY"])
        assert config.quiet is True
        return _result(high=1 if config.base_url.startswith("https://a.") else 0)

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    targets = [_t("a", "high"), _t("b", "no_high")]
    targets[0].api_key = "sk-aaa"
    targets[0].base_url = "https://a.example.com"
    targets[1].api_key = "sk-bbb"
    targets[1].base_url = "https://b.example.com"
    results = _run(calibrate.scan_all(targets))
    assert [r.high_count for r in results] == [1, 0]
    assert seen_keys == ["sk-aaa", "sk-bbb"]


def test_scan_all_failure_recorded(monkeypatch, capsys) -> None:
    async def fake_run(config):
        if "bad" in config.base_url:
            raise RuntimeError("boom")
        return _result()

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    targets = [_t("ok", "no_high"), _t("bad", "high")]
    targets[1].base_url = "https://bad.example.com"
    results = _run(calibrate.scan_all(targets))
    assert results[0] is not None and results[1] is None
    assert "扫描失败" in capsys.readouterr().err


# ── save_raw / render_markdown ──────────────────────────────


def test_save_raw(tmp_path) -> None:
    targets = [_t("好/站 名", "no_high"), _t("坏站", "high")]
    results = [_result(), None]
    paths = calibrate.save_raw(targets, results, tmp_path, "20260829_000000")
    assert len(paths) == 2
    good = json.loads(paths[0].read_text(encoding="utf-8"))
    assert good["probe_suite"] == "2026.08.1"
    bad = json.loads(paths[1].read_text(encoding="utf-8"))
    assert bad == {"error": "scan failed", "label": "high"}


def test_safe_name_edge() -> None:
    assert calibrate._safe_name("a b/c|d") == "a_b_c_d"
    assert calibrate._safe_name("") == "target"
    assert calibrate._safe_name("中转站-1") == "中转站-1"


def test_render_markdown_rows() -> None:
    targets = [
        _t("命中", "high"),
        _t("漏报", "high"),
        _t("误报", "no_high"),
        _t("失败", "high"),
        _t("备注|含竖线", "no_high"),
    ]
    results = [_result(high=2), _result(), _result(high=1), None, _result()]
    stats = calibrate.evaluate(list(zip(targets, results, strict=True)))
    md = calibrate.render_markdown(targets, results, stats)
    assert "✓ 报高危" in md
    assert "✗ 未报高危" in md  # 漏报
    assert "✗ 报高危" in md  # 误报
    assert "扫描失败" in md
    assert "高危0; 高危1" in md  # 关键发现取高危标题
    assert "中危0" not in md  # 中危不出现在关键发现列
    assert "备注\\|含竖线" in md
    assert "探针套件: 2026.08.1" in md
    assert "精确率: 50%" in md and "召回率: 50%" in md


def test_render_markdown_all_failed_and_empty_note() -> None:
    targets = [_t("x", "high")]
    stats = calibrate.evaluate([(targets[0], None)])
    md = calibrate.render_markdown(targets, [None], stats)
    assert "探针套件: -" in md
    assert "精确率: N/A" in md


def test_fmt_ratio_and_md() -> None:
    assert calibrate._fmt_ratio(0.5) == "50%"
    assert calibrate._fmt_ratio(None) == "N/A"
    assert calibrate._md("") == "-"
    assert calibrate._md("a|b") == "a\\|b"


# ── main ────────────────────────────────────────────────────


def test_main_all_match_exit_0(monkeypatch, tmp_path, capsys) -> None:
    path = _targets_file(
        tmp_path,
        [
            _valid_item(),
            _valid_item(name="干净", label="no_high", api_key="sk-b", base_url="https://b.x.com"),
        ],
    )
    monkeypatch.setattr(calibrate, "REPORTS_DIR", tmp_path / "reports")

    async def fake_run(config):
        return _result(high=1) if config.base_url.startswith("https://a.") else _result()

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    assert calibrate.main([path]) == 0
    out_dir = tmp_path / "reports" / "calibration"
    reports = list(out_dir.glob("calibration_*.md"))
    raws = list(out_dir.glob("2026*_*.json"))
    assert len(reports) == 1 and len(raws) == 2
    assert "精确率=100%" in capsys.readouterr().out


def test_main_mismatch_exit_1(monkeypatch, tmp_path) -> None:
    path = _targets_file(tmp_path, [_valid_item(label="no_high")])
    monkeypatch.setattr(calibrate, "REPORTS_DIR", tmp_path / "reports")

    async def fake_run(config):
        return _result(high=1)  # 不应有高危却报了 → 误报

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    assert calibrate.main([path]) == 1


def test_main_scan_failure_exit_2(monkeypatch, tmp_path, capsys) -> None:
    path = _targets_file(tmp_path, [_valid_item()])

    async def fake_run(config):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    assert calibrate.main([path]) == 2
    assert "扫描失败" in capsys.readouterr().err


def test_main_invalid_targets_exit_2(monkeypatch, capsys) -> None:
    assert calibrate.main([str(Path("no-such-file.json"))]) == 2
    assert "目标清单无效" in capsys.readouterr().err


def test_main_quick_output_and_timeout(monkeypatch, tmp_path) -> None:
    path = _targets_file(tmp_path, [_valid_item()])
    captured = {}

    async def fake_run(config):
        captured["config"] = config
        return _result(high=1)  # high 目标命中 → 无误报漏报

    monkeypatch.setattr(calibrate, "run_scan", fake_run)
    out_dir = tmp_path / "custom-out"
    ec = calibrate.main([path, "--quick", "--timeout", "30", "--output", str(out_dir)])
    assert ec == 0
    assert captured["config"].quick is True
    assert captured["config"].timeout == 30
    assert list(out_dir.glob("calibration_*.md"))

"""纵向基准 — 把多次扫描变成可对比的时间序列。

单次扫描回答「现在有没有问题」；纵向基准回答「和上次比，是变好了还是变坏了，
变化是真的还是抖动」。做法是先把扫描结果固化成快照，再对两份快照做配对比较：

- **测试级迁移**：同一条探针上次通过、这次失败（回归），反之是改善；
  用 McNemar 精确检验判断净变化是否超出随机抖动（p < 0.05）。
- **风险等级**：高/中/低危数量与总体等级的变化；等级升高或高危增加一律判回归，
  不依赖显著性——安全问题上宁可误报。
- **模型身份**：同一探针两次返回的 ``model_ret`` 是否一致；不一致说明中转可能
  换了后端模型，这本身就是审计信号。
- **延迟**：两份快照共同通过且都有延迟的探针，比较中位数与 p95；中位数上涨
  超过 50%（样本 ≥ 3）给出告警，但不改变风险结论。
- **可比性**：base_url、请求模型或探针套件版本不同，或共同探针不足一半时，
  判定 ``incomparable``，不给出好坏结论。

用法::

    relay-audit-benchmark capture scan.json --out ~/bench
    relay-audit-benchmark compare bench/a.json bench/b.json
    relay-audit-benchmark history ~/bench
    relay-audit-benchmark trends ~/bench

快照也可以由主程序直接写：``relay-audit --snapshot``。

退出码：0 稳定 / 改善 / 有变化但证据不足；1 判定为回归（``compare``）或存在活跃
回归告警（``trends``）；2 不可比或输入错误。
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import itertools
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any

from relay_audit import REPORTS_DIR
from relay_audit.models import ScanResult
from relay_audit.patterns import redact

SNAPSHOT_VERSION = 1
RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_HIGH_SEVERITIES = {"high", "critical"}


# ── 快照 ──────────────────────────────────────────────────────


@dataclasses.dataclass
class Observation:
    """一条探针的结果，已归一化为跨版本可比的字段。"""

    name: str
    ok: bool
    status: int = 0
    latency_ms: int = 0
    model_ret: str = ""


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value >= 0 else 0
    return 0


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\u4e00-\u9fff-]+", "_", name)[:40] or "scan"


def _risk_from_findings(findings: list[dict[str, Any]]) -> str:
    severities = {str(item.get("severity", "")).lower() for item in findings}
    if severities & _HIGH_SEVERITIES:
        return "HIGH"
    if "medium" in severities:
        return "MEDIUM"
    return "LOW"


def _merge_observations(raw: list[dict[str, Any]], label: str) -> list[Observation]:
    """同名探针合并：任一失败即失败，延迟取最大，状态取首个非零。"""
    merged: dict[str, Observation] = {}
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"{label} 第 {index} 条不是 JSON 对象")
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError(f"{label} 第 {index} 条缺少 name")
        raw_ok = item.get("ok")
        if not isinstance(raw_ok, bool):
            raise ValueError(f"{label} 第 {index} 条的 ok 必须是布尔值")
        observation = Observation(
            name=name,
            ok=raw_ok,
            status=_as_int(item.get("status")),
            latency_ms=_as_int(item.get("latency_ms")),
            model_ret=str(item.get("model_ret") or ""),
        )
        existing = merged.get(name)
        if existing is None:
            merged[name] = observation
            continue
        existing.ok = existing.ok and observation.ok
        existing.latency_ms = max(existing.latency_ms, observation.latency_ms)
        if not existing.status:
            existing.status = observation.status
        if not existing.model_ret:
            existing.model_ret = observation.model_ret
    return list(merged.values())


def snapshot_from_payload(
    payload: dict[str, Any],
    *,
    source: str = "",
    source_sha256: str = "",
    captured_at: str | None = None,
) -> dict[str, Any]:
    """把 ``--json`` 输出或报告目录里的扫描 JSON 归一化为快照。"""
    if not isinstance(payload, dict):
        raise ValueError("扫描结果顶层必须是 JSON 对象")
    raw_tests = payload.get("tests")
    if raw_tests is None:
        raw_tests = payload.get("results")
    if not isinstance(raw_tests, list) or not raw_tests:
        raise ValueError("扫描结果缺少非空的 tests 或 results 数组")
    observations = _merge_observations(raw_tests, "tests")

    raw_findings = payload.get("findings")
    findings: list[dict[str, str]] = []
    if isinstance(raw_findings, list):
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            findings.append(
                {
                    "severity": str(item.get("severity", "")).lower(),
                    "category": str(item.get("category", "")),
                    "title": redact(str(item.get("title", ""))),
                }
            )

    risk = str(payload.get("risk_level", "")).upper()
    if risk not in RISK_RANK:
        risk = _risk_from_findings(findings)

    summary_payload = payload.get("summary")
    summary: dict[str, Any] = summary_payload if isinstance(summary_payload, dict) else {}
    high_raw = summary.get("high", summary.get("high_count"))
    high = _as_int(high_raw)
    medium = _as_int(summary.get("medium"))
    if high_raw is None:
        high = sum(1 for item in findings if item["severity"] in _HIGH_SEVERITIES)
    if summary.get("medium") is None:
        medium = sum(1 for item in findings if item["severity"] == "medium")

    models = sorted({item.model_ret for item in observations if item.model_ret})
    base_url = str(payload.get("base_url", ""))
    return {
        "snapshot_version": SNAPSHOT_VERSION,
        "captured_at": captured_at or dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "source": source,
        "source_sha256": source_sha256,
        "tool_version": str(payload.get("version", "")),
        "probe_suite": str(payload.get("probe_suite", "")),
        "base_url": redact(base_url),
        "model": str(payload.get("model", "")),
        "observed_models": models,
        "risk_level": risk,
        "summary": {
            "high": high,
            "medium": medium,
            "findings": len(findings),
            "tests": len(observations),
            "passed": sum(1 for item in observations if item.ok),
        },
        "findings": findings,
        "observations": [dataclasses.asdict(item) for item in observations],
    }


def load_scan(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    raw = file_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if isinstance(payload, dict) and "snapshot_version" in payload:
        return _validate_snapshot(payload)
    return snapshot_from_payload(
        payload,
        source=file_path.name,
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _validate_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("快照顶层必须是 JSON 对象")
    if payload.get("snapshot_version") != SNAPSHOT_VERSION:
        raise ValueError(
            f"不支持的快照版本: {payload.get('snapshot_version')!r}（当前 {SNAPSHOT_VERSION}）"
        )
    observations = payload.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("快照缺少非空的 observations 数组")
    names: set[str] = set()
    for index, item in enumerate(observations, start=1):
        if not isinstance(item, dict) or not str(item.get("name", "")).strip():
            raise ValueError(f"observations 第 {index} 条缺少 name")
        name = str(item["name"])
        if name in names:
            raise ValueError(f"observations 存在重复探针: {name}")
        names.add(name)
        if not isinstance(item.get("ok"), bool):
            raise ValueError(f"observations 第 {index} 条的 ok 必须是布尔值")
        for field in ("status", "latency_ms"):
            value = item.get(field, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"observations 第 {index} 条的 {field} 必须是非负整数")
    return payload


def load_snapshot(path: str | Path) -> dict[str, Any]:
    """读取快照；如果传入的是原始扫描 JSON，则即时归一化。"""
    file_path = Path(path)
    raw = file_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if isinstance(payload, dict) and "snapshot_version" in payload:
        return _validate_snapshot(payload)
    return snapshot_from_payload(
        payload,
        source=file_path.name,
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def capture_result(result: ScanResult, out_dir: str | Path | None = None) -> Path:
    """把刚完成的扫描写成快照，供后续对比。"""
    snapshot = snapshot_from_payload(result.to_dict())
    snapshot["tool_version"] = result.version
    return save_snapshot(snapshot, out_dir)


def save_snapshot(snapshot: dict[str, Any], out_dir: str | Path | None = None) -> Path:
    if not isinstance(snapshot, dict) or "observations" not in snapshot:
        raise ValueError("不是有效快照")
    _validate_snapshot(snapshot)
    directory = Path(out_dir) if out_dir else Path(REPORTS_DIR) / "benchmarks"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    model = _safe_name(str(snapshot.get("model") or "model"))
    target = directory / f"bench_{stamp}_{model}.json"
    suffix = 1
    while target.exists():
        target = directory / f"bench_{stamp}_{model}_{suffix}.json"
        suffix += 1
    target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def _parse_captured_at(value: object) -> dt.datetime:
    """解析 ISO 时间并统一到 UTC；无时区的时间按 UTC 处理。"""
    text = str(value or "").strip()
    if not text:
        raise ValueError("快照缺少 captured_at")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"无法解析 captured_at: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _history_sort_key(item: dict[str, Any]) -> tuple[dt.datetime, str, str, str]:
    """同刻快照按来源与规范化内容排序，结果不依赖目录或输入顺序。"""
    canonical = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (
        _parse_captured_at(item.get("captured_at")),
        str(item.get("source", "")),
        str(item.get("source_sha256", "")),
        canonical,
    )


def load_history(directory: str | Path) -> list[dict[str, Any]]:
    """读取目录内全部快照，按时间排序（损坏、时间或版本无效的文件跳过）。"""
    snapshots: list[dict[str, Any]] = []
    for path in sorted(Path(directory).glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("snapshot_version") == SNAPSHOT_VERSION:
                snapshot = _validate_snapshot(payload)
                _parse_captured_at(snapshot.get("captured_at"))
                snapshots.append(snapshot)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return sorted(snapshots, key=_history_sort_key)


# ── 统计与比较 ────────────────────────────────────────────────


def mcnemar_exact(b: int, c: int) -> float:
    """McNemar 精确检验（双侧），b/c 是两类不一致对的计数。"""
    if b < 0 or c < 0:
        raise ValueError("不一致对计数不能为负")
    total = b + c
    if total == 0:
        return 1.0
    tail = sum(math.comb(total, k) for k in range(min(b, c) + 1))
    return min(1.0, 2 * tail / (2**total))


def _percentile(values: list[int], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def compare_snapshots(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """对两份快照做配对比较，返回可直接 JSON 序列化的结论。"""
    baseline = _validate_snapshot(baseline)
    candidate = _validate_snapshot(candidate)

    reasons: list[str] = []
    for key, label in (
        ("base_url", "base_url"),
        ("model", "请求模型"),
        ("probe_suite", "探针套件版本"),
    ):
        left = str(baseline.get(key, ""))
        right = str(candidate.get(key, ""))
        if left and right and left != right:
            reasons.append(f"{label}不同：{left} → {right}")

    base_map = {str(item["name"]): item for item in baseline["observations"]}
    cand_map = {str(item["name"]): item for item in candidate["observations"]}
    shared = sorted(set(base_map) & set(cand_map))
    added = sorted(set(cand_map) - set(base_map))
    removed = sorted(set(base_map) - set(cand_map))
    union = set(base_map) | set(cand_map)
    overlap = len(shared) / len(union) if union else 0.0
    if not shared:
        reasons.append("两份快照没有共同探针，无法配对比较。")
    elif overlap < 0.5:
        reasons.append(f"共同探针仅 {len(shared)}/{len(union)}，不足一半，对比不可靠。")

    regressed: list[str] = []
    improved: list[str] = []
    stable_pass = 0
    stable_fail = 0
    model_changes: list[dict[str, str]] = []
    latencies: list[tuple[int, int]] = []
    for name in shared:
        before = base_map[name]
        after = cand_map[name]
        if before["ok"] and not after["ok"]:
            regressed.append(name)
        elif not before["ok"] and after["ok"]:
            improved.append(name)
        elif before["ok"]:
            stable_pass += 1
        else:
            stable_fail += 1
        before_model = str(before.get("model_ret") or "")
        after_model = str(after.get("model_ret") or "")
        if before_model and after_model and before_model != after_model:
            model_changes.append({"name": name, "baseline": before_model, "candidate": after_model})
        before_latency = _as_int(before.get("latency_ms"))
        after_latency = _as_int(after.get("latency_ms"))
        if before["ok"] and after["ok"] and before_latency > 0 and after_latency > 0:
            latencies.append((before_latency, after_latency))

    p_value = mcnemar_exact(len(regressed), len(improved))

    base_risk = str(baseline.get("risk_level", "LOW"))
    cand_risk = str(candidate.get("risk_level", "LOW"))
    base_summary = baseline.get("summary") or {}
    cand_summary = candidate.get("summary") or {}
    base_high = _as_int(base_summary.get("high"))
    cand_high = _as_int(cand_summary.get("high"))
    risk_regressed = (
        RISK_RANK.get(cand_risk, 0) > RISK_RANK.get(base_risk, 0) or cand_high > base_high
    )
    risk_improved = (
        RISK_RANK.get(cand_risk, 0) < RISK_RANK.get(base_risk, 0) or cand_high < base_high
    )

    base_models = set(baseline.get("observed_models") or [])
    cand_models = set(candidate.get("observed_models") or [])
    model_drift: dict[str, Any] = {
        "changed": bool(base_models and cand_models and base_models != cand_models),
        "baseline": sorted(base_models),
        "candidate": sorted(cand_models),
        "per_test": model_changes[:20],
        "per_test_total": len(model_changes),
    }

    latency: dict[str, Any] = {
        "samples": len(latencies),
        "baseline_median_ms": None,
        "candidate_median_ms": None,
        "change_pct": None,
        "regressed": False,
    }
    if latencies:
        before_values = [pair[0] for pair in latencies]
        after_values = [pair[1] for pair in latencies]
        before_median = statistics.median(before_values)
        after_median = statistics.median(after_values)
        latency["baseline_median_ms"] = round(before_median, 1)
        latency["candidate_median_ms"] = round(after_median, 1)
        latency["baseline_p95_ms"] = round(_percentile(before_values, 0.95) or 0, 1)
        latency["candidate_p95_ms"] = round(_percentile(after_values, 0.95) or 0, 1)
        if before_median > 0:
            change = (after_median - before_median) / before_median * 100
            latency["change_pct"] = round(change, 1)
            latency["regressed"] = len(latencies) >= 3 and change >= 50

    significant = p_value < 0.05
    if reasons:
        verdict = "incomparable"
    elif risk_regressed or (significant and len(regressed) > len(improved)):
        verdict = "regressed"
    elif significant and len(improved) > len(regressed):
        verdict = "improved"
    elif regressed or improved or risk_regressed or risk_improved or model_drift["changed"]:
        verdict = "changed"
    else:
        verdict = "stable"

    notes: list[str] = []
    if regressed:
        notes.append(f"{len(regressed)} 项由通过转为失败：" + "、".join(regressed[:6]))
    if improved:
        notes.append(f"{len(improved)} 项由失败转为通过：" + "、".join(improved[:6]))
    if risk_regressed or risk_improved:
        notes.append(f"风险等级 {base_risk} → {cand_risk}，高危 {base_high} → {cand_high}")
    if model_drift["changed"]:
        notes.append(
            "模型身份变化："
            + ", ".join(model_drift["baseline"] or ["-"])
            + " → "
            + ", ".join(model_drift["candidate"] or ["-"])
        )
    if latency["regressed"]:
        notes.append(
            f"延迟中位数 {latency['baseline_median_ms']} → {latency['candidate_median_ms']} ms"
            f"（{latency['change_pct']:+.1f}%，{latency['samples']} 项）"
        )
    if added:
        notes.append(f"新增探针 {len(added)} 项：" + "、".join(added[:6]))
    if removed:
        notes.append(f"缺失探针 {len(removed)} 项：" + "、".join(removed[:6]))
    if verdict == "changed" and (regressed or improved):
        notes.append(f"净变化未达显著（McNemar p={p_value:.3f}），按抖动处理。")

    return {
        "verdict": verdict,
        "comparable": not reasons,
        "reasons": reasons,
        "notes": notes,
        "mcnemar_p": round(p_value, 6),
        "transitions": {
            "regressed": regressed,
            "improved": improved,
            "stable_pass": stable_pass,
            "stable_fail": stable_fail,
            "added": added,
            "removed": removed,
            "overlap": round(overlap, 3),
        },
        "risk": {
            "baseline": base_risk,
            "candidate": cand_risk,
            "baseline_high": base_high,
            "candidate_high": cand_high,
            "regressed": risk_regressed,
            "improved": risk_improved,
        },
        "latency": latency,
        "model_drift": model_drift,
        "baseline": {
            "captured_at": baseline.get("captured_at", ""),
            "source": baseline.get("source", ""),
            "model": baseline.get("model", ""),
        },
        "candidate": {
            "captured_at": candidate.get("captured_at", ""),
            "source": candidate.get("source", ""),
            "model": candidate.get("model", ""),
        },
    }


def analyze_history(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    """按严格上下文分组分析历史；只比较同组内按时间相邻的快照。

    每组至少需要三份快照才给出趋势结论。最新一次回归或历史中出现连续
    两次回归会告警；模型漂移只单独标记，不改变告警状态。
    """
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for snapshot in snapshots:
        validated = _validate_snapshot(snapshot)
        _parse_captured_at(validated.get("captured_at"))
        key = (
            str(validated.get("base_url", "")),
            str(validated.get("model", "")),
            str(validated.get("probe_suite", "")),
        )
        grouped.setdefault(key, []).append(validated)

    groups: list[dict[str, Any]] = []
    for (base_url, model, probe_suite), items in sorted(grouped.items()):
        ordered = sorted(items, key=_history_sort_key)
        comparisons = [
            compare_snapshots(baseline, candidate)
            for baseline, candidate in itertools.pairwise(ordered)
        ]
        latest = ordered[-1]
        result: dict[str, Any] = {
            "base_url": base_url,
            "model": model,
            "probe_suite": probe_suite,
            "snapshot_count": len(ordered),
            "status": "insufficient_data",
            "alert": False,
            "model_drift": any(item["model_drift"]["changed"] for item in comparisons),
            "latest": {
                "captured_at": latest.get("captured_at", ""),
                "source": latest.get("source", ""),
                "risk_level": latest.get("risk_level", ""),
                "summary": dict(latest.get("summary") or {}),
            },
            "trend": None,
            "comparisons": comparisons,
        }
        if len(ordered) >= 3:
            regression_flags = [item["verdict"] == "regressed" for item in comparisons]
            current_run = 0
            max_run = 0
            for regressed in regression_flags:
                current_run = current_run + 1 if regressed else 0
                max_run = max(max_run, current_run)
            trailing_run = 0
            for regressed in reversed(regression_flags):
                if not regressed:
                    break
                trailing_run += 1
            alert_reasons: list[str] = []
            if regression_flags[-1]:
                alert_reasons.append("latest_regression")
            if trailing_run >= 2:
                alert_reasons.append("consecutive_regressions")
            result["status"] = comparisons[-1]["verdict"]
            result["alert"] = bool(alert_reasons)
            result["trend"] = {
                "latest_verdict": comparisons[-1]["verdict"],
                "regression_count": sum(regression_flags),
                "consecutive_regressions": trailing_run,
                "max_consecutive_regressions": max_run,
                "alert_reasons": alert_reasons,
            }
        groups.append(result)

    return {
        "snapshot_count": len(snapshots),
        "group_count": len(groups),
        "alert_count": sum(1 for group in groups if group["alert"]),
        "groups": groups,
    }


# ── 输出 ──────────────────────────────────────────────────────


def render_comparison(payload: dict[str, Any]) -> str:
    label = {
        "stable": "稳定",
        "improved": "改善",
        "regressed": "回归",
        "changed": "有变化（证据不足）",
        "incomparable": "不可比",
    }.get(payload["verdict"], payload["verdict"])
    lines = [f"结论: {label}", f"McNemar p = {payload['mcnemar_p']:.4f}"]
    transitions = payload["transitions"]
    lines.append(
        "探针: "
        f"回归 {len(transitions['regressed'])} | 改善 {len(transitions['improved'])} | "
        f"稳定通过 {transitions['stable_pass']} | 稳定失败 {transitions['stable_fail']} | "
        f"重叠 {transitions['overlap']:.0%}"
    )
    for note in payload["notes"]:
        lines.append(f"- {note}")
    for reason in payload["reasons"]:
        lines.append(f"! {reason}")
    return "\n".join(lines)


def _short_endpoint(value: object, width: int = 24) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    text = text.split("://", 1)[-1].rstrip("/")
    return text if len(text) <= width else text[: width - 1] + "…"


def render_history(snapshots: list[dict[str, Any]]) -> str:
    if not snapshots:
        return "没有可用的快照。"
    header = (
        f"{'时间':<25} {'端点':<24} {'模型':<24} {'风险':<7} {'高/中':<7} "
        f"{'通过':<9} {'中位延迟':>9}"
    )
    lines = [header, "-" * len(header)]
    previous: dict[str, Any] | None = None
    suppressed = 0
    for item in snapshots:
        summary = item.get("summary") or {}
        passed = f"{int(summary.get('passed') or 0)}/{int(summary.get('tests') or 0)}"
        observations = [
            _as_int(obs.get("latency_ms"))
            for obs in item.get("observations", [])
            if obs.get("ok") and _as_int(obs.get("latency_ms")) > 0
        ]
        median = f"{statistics.median(observations):.0f} ms" if observations else "-"
        risk = str(item.get("risk_level", "?"))
        delta = ""
        if previous is not None:
            same_context = all(
                str(previous.get(key, "")) == str(item.get(key, ""))
                for key in ("base_url", "model", "probe_suite")
            )
            risk_delta = RISK_RANK.get(risk, 0) - RISK_RANK.get(str(previous.get("risk_level")), 0)
            if same_context and risk_delta > 0:
                delta = " ↑"
            elif same_context and risk_delta < 0:
                delta = " ↓"
            elif risk_delta:
                suppressed += 1
        captured = str(item.get("captured_at", ""))
        model = str(item.get("model") or "-")
        endpoint = _short_endpoint(item.get("base_url"))
        lines.append(
            f"{captured:<25} "
            f"{endpoint:<24} "
            f"{model:<24} "
            f"{risk + delta:<7} "
            f"{int(summary.get('high') or 0)}/{int(summary.get('medium') or 0)}   "
            f"{passed:<9} {median:>9}"
        )
        previous = item
    if suppressed:
        lines.append("")
        lines.append(f"注：{suppressed} 处相邻快照的端点、模型或探针套件不同，已跳过风险箭头。")
    return "\n".join(lines)


def render_trends(payload: dict[str, Any]) -> str:
    groups = payload["groups"]
    if not groups:
        return "没有可用的快照。"
    lines = [f"快照 {payload['snapshot_count']} 份，分组 {payload['group_count']} 个。"]
    for group in groups:
        context = (
            f"{_short_endpoint(group['base_url'])} / {group['model'] or '-'} / "
            f"{group['probe_suite'] or '-'}"
        )
        lines.append(
            f"{context}: snapshots={group['snapshot_count']} status={group['status']} "
            f"alert={str(group['alert']).lower()} "
            f"model_drift={str(group['model_drift']).lower()}"
        )
        trend = group["trend"]
        if trend is None:
            lines.append("- 数据不足：至少需要 3 份同组快照，不生成趋势告警。")
        else:
            reasons = ", ".join(trend["alert_reasons"]) or "none"
            lines.append(
                f"- 最新: {trend['latest_verdict']}；回归 {trend['regression_count']} 次；"
                f"当前连续回归 {trend['consecutive_regressions']} 次；告警原因: {reasons}"
            )
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────


def _capture_paths(path: Path, out_dir: str | None) -> list[Path]:
    sources = sorted(path.glob("*.json")) if path.is_dir() else [path]
    return [save_snapshot(load_scan(item), out_dir) for item in sources]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relay-audit-benchmark",
        description="纵向基准：固化扫描快照，比较两次扫描的回归/改善与模型漂移",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("capture", help="把扫描 JSON（或目录内全部 JSON）固化为快照")
    capture.add_argument("source", help="扫描结果 JSON 文件或目录")
    capture.add_argument("--out", help="快照输出目录（默认 <报告目录>/benchmarks）")

    compare = sub.add_parser("compare", help="比较两份快照或扫描结果")
    compare.add_argument("baseline", help="基线快照 / 扫描 JSON")
    compare.add_argument("candidate", help="候选快照 / 扫描 JSON")
    compare.add_argument("--json", action="store_true", help="输出 JSON 而不是文本")
    compare.add_argument("--markdown", help="同时把结论写入指定 Markdown 文件")

    history = sub.add_parser("history", help="按时间列出目录内快照")
    history.add_argument("directory", help="快照目录")
    history.add_argument("--json", action="store_true", help="输出 JSON 而不是表格")

    trends = sub.add_parser("trends", help="按端点、模型和探针套件分组分析历史趋势")
    trends.add_argument("directory", help="快照目录")
    trends.add_argument("--json", action="store_true", help="输出 JSON 而不是文本")
    return parser


def _render_markdown(payload: dict[str, Any]) -> str:
    transitions = payload["transitions"]
    lines = [
        "# Relay Audit 纵向基准报告",
        "",
        f"- 结论: **{payload['verdict']}**",
        f"- McNemar p: {payload['mcnemar_p']:.4f}",
        f"- 基线: {payload['baseline']['captured_at']} / {payload['baseline']['model']}",
        f"- 候选: {payload['candidate']['captured_at']} / {payload['candidate']['model']}",
        f"- 回归: {len(transitions['regressed'])}；改善: {len(transitions['improved'])}；"
        + f"稳定通过: {transitions['stable_pass']}；稳定失败: {transitions['stable_fail']}",
        "",
        "## 说明",
        "",
    ]
    lines += [f"- {item}" for item in payload["notes"]] or ["- 无"]
    if payload["reasons"]:
        lines += ["", "## 不可比原因", ""]
        lines += [f"- {item}" for item in payload["reasons"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "capture":
            source = Path(args.source)
            if not source.exists():
                print(f"  [x] 路径不存在: {source}", file=sys.stderr)
                return 2
            if source.is_dir() and not any(source.glob("*.json")):
                print(f"  [x] 目录内没有 JSON 扫描结果: {source}", file=sys.stderr)
                return 2
            paths = _capture_paths(source, args.out)
            for path in paths:
                print(f"  快照: {path}")
            return 0

        if args.command == "compare":
            result = compare_snapshots(
                load_snapshot(args.baseline),
                load_snapshot(args.candidate),
            )
            if args.markdown:
                Path(args.markdown).write_text(_render_markdown(result), encoding="utf-8")
                if not args.json:
                    print(f"  报告: {args.markdown}")
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(render_comparison(result))
            if result["verdict"] == "regressed":
                return 1
            if result["verdict"] == "incomparable":
                return 2
            return 0

        directory = Path(args.directory)
        if not directory.is_dir():
            print(f"  [x] 快照目录不存在: {directory}", file=sys.stderr)
            return 2
        snapshots = load_history(directory)
        if args.command == "trends":
            result = analyze_history(snapshots)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(render_trends(result))
            return int(result["alert_count"] > 0)
        if args.json:
            print(json.dumps(snapshots, ensure_ascii=False, indent=2))
        else:
            print(render_history(snapshots))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"  [x] 基准处理失败: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover — 模块入口
    raise SystemExit(main())

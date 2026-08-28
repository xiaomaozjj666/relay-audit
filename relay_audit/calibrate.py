"""检测有效性校准 — 对已知底细的中转站批量扫描，统计误报 / 漏报。

审计工具的核心资产是检测结论的可信度。本模块把"校准"变成可复现的流程：
对一组已知真实情况（label）的中转站执行完整扫描，将工具的判定与真实情况
对照，输出混淆矩阵、精确率与召回率，用于把严重等级从经验值校准为实证值。

用法::

    python -m relay_audit.calibrate targets.json [--quick] [--timeout N] [--output DIR]

或安装后使用 ``relay-audit-calibrate targets.json``。

目标清单格式（JSON 数组）::

    [
      {"name": "直连官方", "base_url": "https://api.example.com",
       "api_key": "sk-...", "label": "no_high", "note": "官方 API，不应有高危"},
      {"name": "偷换站A", "base_url": "https://relay.example.com",
       "api_key": "sk-...", "label": "high", "model": "gpt-4o",
       "note": "已知 gpt-4o 被换成小模型"}
    ]

label 取值：
  no_high — 该目标不应触发高危发现（干净直连 / 正常中转）
  high    — 该目标应触发高危发现（已知偷换 / 已知危险行为）

产出（写入 --output 目录，默认 <报告目录>/calibration）：
  calibration_<时间戳>.md   汇总报告（混淆矩阵 + 精确率/召回率 + 每目标明细）
  <时间戳>_<目标名>.json    每个目标的完整 ScanResult（不含 API Key）

退出码：0 全部判定与真实情况一致；1 存在误报/漏报；2 有目标扫描失败或清单无效。
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from relay_audit import REPORTS_DIR
from relay_audit.models import ScanConfig, ScanResult
from relay_audit.scanner import run_scan

VALID_LABELS = ("high", "no_high")


@dataclasses.dataclass
class CalibrationTarget:
    """一条校准目标：label 是该中转站的真实情况（基准真值）。"""

    name: str
    base_url: str
    api_key: str
    label: str  # "high" = 应触发高危发现；"no_high" = 不应触发
    model: str = ""  # 可选：指定模型，留空则自动选择
    note: str = ""


def load_targets(path: str | Path) -> list[CalibrationTarget]:
    """读取并校验目标清单 JSON；结构或取值不合法时抛 ValueError。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not data:
        raise ValueError("目标清单顶层必须是非空 JSON 数组")
    targets: list[CalibrationTarget] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"第 {i + 1} 项不是 JSON 对象")
        missing = [k for k in ("name", "base_url", "api_key", "label") if not item.get(k)]
        if missing:
            raise ValueError(f"第 {i + 1} 项缺少必填字段: {', '.join(missing)}")
        if item["label"] not in VALID_LABELS:
            raise ValueError(
                f"第 {i + 1} 项 label 必须是 {' / '.join(VALID_LABELS)}，得到 {item['label']!r}"
            )
        targets.append(
            CalibrationTarget(
                name=str(item["name"]),
                base_url=str(item["base_url"]),
                api_key=str(item["api_key"]),
                label=str(item["label"]),
                model=str(item.get("model", "") or ""),
                note=str(item.get("note", "") or ""),
            )
        )
    return targets


def flagged(result: ScanResult) -> bool:
    """工具的判定：是否触发高危发现。"""
    return result.high_count > 0


def evaluate(rows: list[tuple[CalibrationTarget, ScanResult | None]]) -> dict[str, Any]:
    """与基准真值对照，计算混淆矩阵。

    扫描失败（None）的目标不计入混淆矩阵，单独以 failures 返回；
    precision / recall 分母为 0 时返回 None（此时该指标无意义）。
    """
    tp = fp = tn = fn = 0
    failures = 0
    for target, result in rows:
        if result is None:
            failures += 1
            continue
        hit = flagged(result)
        if target.label == "high":
            if hit:
                tp += 1
            else:
                fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / (tp + fn) if (tp + fn) else None,
        "failures": failures,
        "total": len(rows),
    }


async def scan_all(
    targets: list[CalibrationTarget], quick: bool = False, timeout: int = 60
) -> list[ScanResult | None]:
    """逐个执行完整扫描（串行，避免跨目标限流相互干扰）。"""
    results: list[ScanResult | None] = []
    for t in targets:
        os.environ["RELAY_API_KEY"] = t.api_key
        config = ScanConfig(
            base_url=t.base_url, model=t.model, timeout=timeout, quick=quick, quiet=True
        )
        try:
            result = await run_scan(config)
            print(
                f"  [{t.label}] {t.name}: 高危 {result.high_count} "
                f"中危 {result.med_count} 低危 {result.low_count}",
                flush=True,
            )
            results.append(result)
        except Exception as e:
            print(f"  [x] {t.name}: 扫描失败 - {e}", file=sys.stderr)
            results.append(None)
    return results


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\u4e00-\u9fff-]+", "_", name)[:40] or "target"


def save_raw(
    targets: list[CalibrationTarget],
    results: list[ScanResult | None],
    out_dir: Path,
    ts: str,
) -> list[Path]:
    """每个目标保存一份完整 ScanResult JSON（不含 API Key），返回路径列表。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for t, r in zip(targets, results, strict=True):
        path = out_dir / f"{ts}_{_safe_name(t.name)}.json"
        payload: dict[str, Any] = (
            r.to_dict() if r is not None else {"error": "scan failed", "label": t.label}
        )
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        paths.append(path)
    return paths


def _fmt_ratio(value: float | None) -> str:
    return f"{value:.0%}" if value is not None else "N/A"


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ") or "-"


def render_markdown(
    targets: list[CalibrationTarget],
    results: list[ScanResult | None],
    stats: dict[str, Any],
) -> str:
    """渲染校准报告（混淆矩阵 + 每目标明细）。"""
    probe = next((r.probe_suite for r in results if r is not None), "-")
    lines = [
        "# Relay Audit 检测有效性校准报告",
        "",
        f"- 时间: {dt.datetime.now():%Y-%m-%d %H:%M:%S}",
        f"- 探针套件: {probe or '-'}",
        "",
        "## 混淆矩阵",
        "",
        f"- TP（应有高危，工具报了）: {stats['tp']}",
        f"- FN（应有高危，工具漏了）: {stats['fn']}",
        f"- TN（不应有高危，工具没报）: {stats['tn']}",
        f"- FP（不应有高危，工具误报）: {stats['fp']}",
        f"- 扫描失败: {stats['failures']}/{stats['total']}",
        f"- 高危判定精确率: {_fmt_ratio(stats['precision'])}",
        f"- 高危判定召回率: {_fmt_ratio(stats['recall'])}",
        "",
        "## 每目标明细",
        "",
        "| 目标 | 真实情况 | 工具判定 | 风险 | 高/中/低 | 关键发现 | 备注 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t, r in zip(targets, results, strict=True):
        if r is None:
            lines.append(f"| {_md(t.name)} | {t.label} | 扫描失败 | - | - | - | {_md(t.note)} |")
            continue
        hit = flagged(r)
        verdict = f"{'✓' if (t.label == 'high') == hit else '✗'} " + (
            "报高危" if hit else "未报高危"
        )
        titles = [f.title for f in r.findings if f.severity.rank >= 3][:3]
        lines.append(
            f"| {_md(t.name)} | {t.label} | {verdict} | {r.risk_level} "
            f"| {r.high_count}/{r.med_count}/{r.low_count} | {_md('; '.join(titles))} "
            f"| {_md(t.note)} |"
        )
    lines += [
        "",
        "> 精确率 = 报对的高危 / 所有报出的高危；召回率 = 报对的高危 / 所有应有高危。",
        "多轮校准后可据此调整 analysis.py 中各 Finding 的严重等级。",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="对已知底细的中转站批量扫描，统计误报/漏报（检测有效性校准）",
    )
    parser.add_argument("targets", help="目标清单 JSON 路径（格式见模块 docstring）")
    parser.add_argument("--quick", action="store_true", help="快速模式（同 relay-audit --quick）")
    parser.add_argument("--timeout", type=int, default=60, help="请求超时秒数（默认 60）")
    parser.add_argument("--output", help="报告输出目录（默认 <报告目录>/calibration）")
    args = parser.parse_args(argv)

    try:
        targets = load_targets(args.targets)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"  [x] 目标清单无效: {e}", file=sys.stderr)
        return 2

    out_dir = Path(args.output) if args.output else Path(REPORTS_DIR) / "calibration"
    mode = "快速" if args.quick else "完整"
    print(f"  [i] 校准 {len(targets)} 个目标（{mode}模式）...", flush=True)
    results = asyncio.run(scan_all(targets, quick=args.quick, timeout=args.timeout))

    stats = evaluate(list(zip(targets, results, strict=True)))
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = save_raw(targets, results, out_dir, ts)
    report_path = out_dir / f"calibration_{ts}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(targets, results, stats))

    print(
        f"\n  TP={stats['tp']} FN={stats['fn']} TN={stats['tn']} FP={stats['fp']}"
        f" 失败={stats['failures']}"
        f" | 精确率={_fmt_ratio(stats['precision'])} 召回率={_fmt_ratio(stats['recall'])}"
    )
    print(f"  报告: {report_path}")
    print(f"  原始结果: {len(paths)} 个 JSON（{out_dir}）")

    if stats["failures"]:
        return 2
    if stats["fp"] or stats["fn"]:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover — 模块入口
    raise SystemExit(main())

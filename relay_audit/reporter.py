"""报告生成 — HTML / 终端 / JSON，对标 api-relay-audit 的 reporter.py"""

from __future__ import annotations

import datetime as dt
import html as htmlmod
import json
import os
from typing import Any

from relay_audit.models import ChatResult, Finding, ScanResult
from relay_audit.patterns import (
    CAT_CN,
    DIAGNOSTIC_PREFIXES,
    REFUSAL_PATTERNS,
    REFUSED_STATUS,
    SAFETY_TEST_NAMES,
    SEV_CN,
    redact,
    short,
)


# ═══════════════════════════════════════════════════════════════
# 通过率计算
# ═══════════════════════════════════════════════════════════════


def _is_diagnostic(r: ChatResult) -> bool:
    return any(r.name.startswith(p) for p in DIAGNOSTIC_PREFIXES)


def _is_safety_refused(r: ChatResult) -> bool:
    return r.name in SAFETY_TEST_NAMES and not r.ok and r.status in REFUSED_STATUS


def _is_refused_by_pattern(r: ChatResult) -> bool:
    return bool(r.content and REFUSAL_PATTERNS.search(r.content))


def compute_pass_rate(results: list[ChatResult]) -> tuple[int, int]:
    """计算通过率 (effective_ok, total)。诊断测试不计入分母。"""
    graded = [r for r in results if not _is_diagnostic(r)]
    total = len(graded)
    effective_ok = sum(
        1 for r in graded if r.ok or _is_safety_refused(r) or _is_refused_by_pattern(r)
    )
    return effective_ok, total


# ═══════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════


def esc(text: str) -> str:
    return htmlmod.escape(redact(str(text)))


def _project_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _reports_dir() -> str:
    d = os.path.join(_project_dir(), "reports")
    os.makedirs(d, exist_ok=True)
    _clean_old_reports(d, days=7)
    return d


# ═══════════════════════════════════════════════════════════════
# 终端输出
# ═══════════════════════════════════════════════════════════════


def print_terminal(result: ScanResult) -> None:
    try:
        _print_rich(result)
    except ImportError:
        _print_plain(result)


def _print_plain(result: ScanResult) -> None:
    print()
    for f in result.findings:
        sev = SEV_CN.get(f.severity.value, f.severity.value)
        cat = CAT_CN.get(f.category, f.category)
        reason = f" | {f.reason}" if f.reason else ""
        print(f"  [{sev}][{cat}] {f.title}{reason}")
        print(f"       {f.detail}")
    if not result.findings:
        print("  [OK] 未发现异常")
    ok = [r for r in result.results if r.ok]
    lats = [r.latency_ms for r in ok]
    avg = sum(lats) / len(lats) if lats else 0
    tps = [r.tokens_per_second for r in ok if r.tokens_per_second]
    avg_tps = f"{sum(tps) / len(tps):.1f}" if tps else "-"
    print(f"  {'-' * 40}")
    print(
        f"  耗时 {result.duration_s:.0f}s | 测试 {len(result.results)} 项 | "
        f"高危 {result.high_count} 中危 {result.med_count} 低危 {result.low_count} | "
        f"延迟 {avg:.0f}ms | {avg_tps} tok/s  | 风险 {result.risk_level}"
    )


def _print_rich(result: ScanResult) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
    ok = [r for r in result.results if r.ok]
    effective_ok, total = compute_pass_rate(result.results)
    lats = [r.latency_ms for r in ok]
    avg = sum(lats) / len(lats) if lats else 0
    mx = max(lats) if lats else 0
    tps = [r.tokens_per_second for r in ok if r.tokens_per_second]
    avg_tps = sum(tps) / len(tps) if tps else 0
    risk_st = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}.get(
        result.risk_level, "bold white"
    )

    console.print()
    console.print(
        Panel(
            f"[bold]{result.config.base_url}[/]\n"
            f"模型: [cyan]{result.config.model}[/]  |  "
            f"[{risk_st}]风险 {result.risk_level}[/]  |  "
            f"耗时 {result.duration_s:.0f}s  |  测试 {len(result.results)} 项",
            title="[bold]Relay Audit[/]",
            border_style="blue",
        )
    )

    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats.add_column(justify="center", min_width=10)
    stats.add_column(justify="center", min_width=10)
    stats.add_column(justify="center", min_width=10)
    stats.add_column(justify="center", min_width=10)
    stats.add_row(
        f"[bold red]{result.high_count}[/] 高危",
        f"[bold yellow]{result.med_count}[/] 中危",
        f"[bold blue]{result.low_count}[/] 低危",
        f"[dim]{len(result.findings)}[/] 总计",
    )
    console.print(stats)

    if result.findings:
        t = Table(box=box.ROUNDED, title="检测发现", title_style="bold")
        t.add_column("", width=6)
        t.add_column("类别", width=8)
        t.add_column("问题", ratio=3)
        t.add_column("详情", ratio=2)
        colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        for f in result.findings:
            c = colors.get(f.severity.value, "white")
            sev = SEV_CN.get(f.severity.value, f.severity.value)
            cat = CAT_CN.get(f.category, f.category)
            detail = short(f.detail, 60)
            reason = f"\n[dim italic]{f.reason}[/]" if f.reason else ""
            t.add_row(
                f"[{c}]{sev}[/]",
                f"[dim]{cat}[/]",
                f"{f.title}{reason}",
                f"[dim]{detail}[/]",
            )
        console.print(t)
    else:
        console.print("[green]✓[/] 未发现异常")

    rt = Table(box=box.SIMPLE, title="测试明细", title_style="bold")
    rt.add_column("项目", min_width=14)
    rt.add_column("结果", width=6, justify="center")
    rt.add_column("延迟", width=8, justify="right")
    rt.add_column("tok/s", width=7, justify="right")
    rt.add_column("请求模型", max_width=20)
    rt.add_column("返回模型", max_width=20)

    for r in result.results:
        refused = _is_refused_by_pattern(r)
        if _is_safety_refused(r):
            ok_cls = "[yellow]拒[/]"
        elif refused:
            ok_cls = "[green]✓[/]"
        elif r.ok:
            ok_cls = "[green]✓[/]"
        else:
            ok_cls = "[red]✗[/]"
        tps_s = f"{r.tokens_per_second:.1f}" if r.tokens_per_second else "-"
        lat_color = (
            "red" if r.latency_ms > 3000 else "yellow" if r.latency_ms > 1000 else ""
        )
        lat_s = (
            f"[{lat_color}]{r.latency_ms}ms[/]" if lat_color else f"{r.latency_ms}ms"
        )
        st = " [dim][流][/]" if r.streaming else ""
        rt.add_row(
            f"{r.name}{st}",
            ok_cls,
            lat_s,
            tps_s,
            f"[dim]{r.model_req}[/]",
            f"[dim]{r.model_ret or '-'}[/]",
        )
    console.print(rt)
    console.print(
        f"  [dim]延迟 avg={avg:.0f}ms max={mx}ms  |  {avg_tps:.1f} tok/s  |  "
        f"通过 {effective_ok}/{total}[/]"
    )
    console.print()


def print_json(result: ScanResult) -> None:
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


# ═══════════════════════════════════════════════════════════════
# HTML 报告生成
# ═══════════════════════════════════════════════════════════════


def _calc_score(h: int, m: int, lo: int) -> tuple[int, str]:
    score = 100 - h * 15 - m * 5 - lo * 2
    score = max(10, score)
    if score >= 90:
        color = "#27ae60"
    elif score >= 70:
        color = "#f39c12"
    elif score >= 50:
        color = "#e67e22"
    else:
        color = "#e74c3c"
    return score, color


def _count_findings(findings: list[Finding]) -> tuple[int, int, int]:
    seen: set[tuple[str, str]] = set()
    h = m = lo = 0
    for f in findings:
        key = (f.model_name or "(default)", f.title)
        if key in seen:
            continue
        seen.add(key)
        sev = f.severity.value
        if sev in ("critical", "high"):
            h += 1
        elif sev == "medium":
            m += 1
        elif sev in ("low", "info"):
            lo += 1
    return h, m, lo


def _response_preview(content: str, max_len: int = 200) -> str:
    if not content:
        return '<span class="empty">无响应</span>'
    preview = redact(content).replace("\r", "").replace("\n", " ").strip()
    if len(preview) > max_len:
        preview = preview[:max_len] + "…"
    return f'<span class="resp-preview">{esc(preview)}</span>'


def _perf_stats(result: ScanResult) -> dict[str, Any]:
    ok = [r for r in result.results if r.ok]
    if not ok:
        return {"avg_lat": 0, "max_lat": 0, "avg_tps": 0, "ok_count": 0}
    lats = [r.latency_ms for r in ok]
    tps = [r.tokens_per_second for r in ok if r.tokens_per_second]
    return {
        "avg_lat": round(sum(lats) / len(lats), 0),
        "max_lat": max(lats),
        "avg_tps": round(sum(tps) / len(tps), 1) if tps else 0,
        "ok_count": len(ok),
    }


def _generate_recommendations(result: ScanResult) -> tuple[str, int]:
    recs: list[str] = []
    cats = {f.category for f in result.findings}

    if result.high_count:
        recs.append("存在高危问题，建议立即排查中转服务的安全性和模型真实性")
    if "identity" in cats:
        recs.append(
            "检测到模型身份异常，中转可能替换了实际使用的模型，建议对比官方 API 输出"
        )
    if "security" in cats:
        recs.append("安全测试发现风险，建议确认中转服务是否对模型输出做了安全过滤")
    if any("Token" in f.title or "token" in f.title.lower() for f in result.findings):
        recs.append("Token 计费存在异常，建议核对中转的计费规则是否合理")
    if any("延迟" in f.title or "并发" in f.title for f in result.findings):
        recs.append("性能指标存在波动，建议在不同时段多次测试确认稳定性")
    if any("模型名" in f.title for f in result.findings):
        recs.append("发现可疑模型名，中转可能使用了自定义路由或模型别名")
    if result.risk_level == "LOW" and not result.high_count:
        recs.append("未发现高危问题，中转服务整体表现正常")
    if not recs:
        recs.append("检测完成，未发现明显异常")

    items = "".join(f"<li>{esc(r)}</li>" for r in recs)
    return f'<ul class="rec-list">{items}</ul>', len(recs)


def generate_html(result: ScanResult) -> str:
    """精简紧凑式报告 — 聚焦关键问题"""
    base_url, model, risk = (
        result.config.base_url,
        result.config.model,
        result.risk_level,
    )
    perf = _perf_stats(result)
    ok_lats = [r.latency_ms for r in result.results if r.ok]
    max_lat = max(ok_lats) if ok_lats else 1

    risk_cn = {"HIGH": "高风险", "MEDIUM": "中风险", "LOW": "低风险"}
    risk_color = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#059669"}
    sev_cn = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }
    cat_cn = {
        "security": "安全",
        "identity": "身份",
        "quality": "质量",
        "performance": "性能",
        "model": "模型",
        "general": "通用",
    }

    effective_ok, total = compute_pass_rate(result.results)
    pass_rate_pct = int(effective_ok / total * 100) if total else 0
    pass_rate = f"{effective_ok}/{total}"

    h_count, m_count, lo_count = _count_findings(result.findings)
    score_val, score_color = _calc_score(h_count, m_count, lo_count)
    badge_color = risk_color.get(risk, "#6b7280")

    rec_html, rec_count = _generate_recommendations(result)

    high_med_findings = [f for f in result.findings if f.severity.rank >= 2]
    low_info_findings = [f for f in result.findings if f.severity.rank <= 1]

    def _finding_row(f: Finding) -> str:
        sc = f.severity.value
        sv = sev_cn.get(sc, sc)
        cc = cat_cn.get(f.category, f.category)
        reason = f" <span class='r'>{esc(f.reason)}</span>" if f.reason else ""
        model_tag = (
            f" <span class='model-tag'>{esc(f.model_name)}</span>"
            if f.model_name
            else ""
        )
        return (
            f'<tr class="sev-{sc}">'
            f'<td><span class="tag tag-{sc}">{sv}</span></td>'
            f'<td><span class="cat cat-{esc(f.category)}">{cc}</span></td>'
            f'<td><div class="finding-title">{esc(f.title)}{model_tag}</div>'
            f'<div class="finding-detail">{esc(f.detail)}{reason}</div></td>'
            f"</tr>\n"
        )

    frows_high_med = "".join(_finding_row(f) for f in high_med_findings)
    frows_low_info = "".join(_finding_row(f) for f in low_info_findings)

    fail_tests = []
    ok_tests = []
    for r in result.results:
        refused = _is_refused_by_pattern(r)
        if _is_safety_refused(r):
            s_tag, s_cls, row_cls = "拒绝", "refused", "ok"
        elif refused:
            s_tag, s_cls, row_cls = "拒绝", "refused", "ok"
        elif r.ok:
            s_tag, s_cls, row_cls = "通过", "ok", "ok"
        else:
            s_tag, s_cls, row_cls = "失败", "fail", "fail"
        if row_cls == "fail":
            fail_tests.append((r, s_tag, s_cls, row_cls))
        else:
            ok_tests.append((r, s_tag, s_cls, row_cls))

    def _test_row(r: ChatResult, s_tag: str, s_cls: str, row_cls: str) -> str:
        st = " <span class='stream-tag'>流</span>" if r.streaming else ""
        pct = min(100, int(r.latency_ms / max_lat * 100)) if r.ok and max_lat else 0
        bc = (
            "#dc2626"
            if r.latency_ms > 3000
            else "#d97706"
            if r.latency_ms > 1000
            else "#059669"
            if r.ok
            else "#9ca3af"
        )
        bar = (
            f'<div class="bt"><div class="bf" style="width:{pct}%;background:{bc}"></div></div>'
            if r.ok
            else ""
        )
        preview = _response_preview(r.content, 80)
        tps = f"{r.tokens_per_second:.1f}" if r.tokens_per_second else "-"
        model_ret = esc(r.model_ret) if r.model_ret else "-"
        return (
            f'<tr class="t-{row_cls}">'
            f'<td><span class="test-name">{esc(r.name)}</span>{st}</td>'
            f'<td><span class="s-{s_cls}">{s_tag}</span></td>'
            f'<td class="n">{r.latency_ms}ms{bar}</td>'
            f'<td class="n">{tps}</td>'
            f'<td class="rp">{preview}</td>'
            f'<td class="n model-col">{model_ret}</td>'
            f"</tr>\n"
        )

    rrows_fail = "".join(_test_row(r, s, c, rc) for r, s, c, rc in fail_tests)
    rrows_ok = "".join(_test_row(r, s, c, rc) for r, s, c, rc in ok_tests)
    fail_count = len(fail_tests)
    ok_count = len(ok_tests)

    sd = result.started_at[:19].replace("T", " ") if result.started_at else "-"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relay Audit | {esc(base_url)}</title>
<style>
:root {{
  --bg: #f8fafc;
  --card: #ffffff;
  --text: #0f172a;
  --muted: #64748b;
  --border: #e2e8f0;
  --red: #dc2626;
  --amber: #d97706;
  --green: #059669;
  --blue: #2563eb;
  --radius: 8px;
}}
* {{ margin:0; padding:0; box-sizing:border-box }}
body {{
  background: var(--bg);
  font: 13px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  color: var(--text);
  padding: 16px 12px;
  max-width: 920px;
  margin: 0 auto;
}}
.card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  margin-bottom: 12px;
}}
h2 {{
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 6px;
}}
h2 .count {{
  background: #f1f5f9;
  color: var(--muted);
  font-size: 11px;
  padding: 1px 7px;
  border-radius: 8px;
  font-weight: 500;
}}
.summary-bar {{
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 14px 16px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 12px;
  flex-wrap: wrap;
}}
.risk-level {{
  font-size: 18px;
  font-weight: 700;
  padding: 5px 14px;
  border-radius: 6px;
  color: #fff;
  white-space: nowrap;
}}
.score-num {{
  font-size: 28px;
  font-weight: 800;
  line-height: 1;
  min-width: 50px;
}}
.score-label {{ font-size: 10px; color: var(--muted); text-align: center }}
.pass-info {{ flex: 1; min-width: 150px }}
.pass-label {{ font-size: 12px; color: var(--muted); margin-bottom: 4px }}
.pass-value {{ font-size: 15px; font-weight: 600 }}
.pass-bar-sm {{ height: 4px; background: var(--border); border-radius: 2px; margin-top: 4px; overflow: hidden }}
.pass-fill-sm {{ height: 4px; border-radius: 2px; background: var(--green) }}
.meta-line {{
  font-size: 11px;
  color: var(--muted);
  margin-left: auto;
  text-align: right;
}}
.url-text {{ font-size: 12px; color: var(--muted); word-break: break-all; margin-bottom: 2px }}
.stats-row {{
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}}
.stat-pill {{
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 5px;
}}
.stat-pill-high {{ background: #fef2f2; color: var(--red) }}
.stat-pill-med {{ background: #fffbeb; color: var(--amber) }}
.stat-pill-low {{ background: #eff6ff; color: var(--blue) }}
.stat-pill-ok {{ background: #f0fdf4; color: var(--green) }}
.stat-pill-num {{ font-size: 15px; font-weight: 700 }}
details {{ margin-top: 8px }}
summary {{
  cursor: pointer;
  font-size: 12px;
  color: var(--muted);
  padding: 6px 10px;
  background: #f8fafc;
  border-radius: 4px;
  list-style: none;
  user-select: none;
  border: 1px solid var(--border);
}}
summary::-webkit-details-marker {{ display: none }}
summary::before {{ content: "▶ "; font-size: 9px; display: inline-block; transition: transform .15s }}
details[open] summary::before {{ transform: rotate(90deg) }}
.rec-list {{ list-style: none; padding: 0 }}
.rec-list li {{
  padding: 7px 10px;
  margin: 3px 0;
  background: #f8fafc;
  border-left: 3px solid var(--blue);
  border-radius: 0 4px 4px 0;
  font-size: 12px;
}}
.tb {{ width: 100%; border-collapse: collapse; font-size: 12px }}
.tb th {{
  background: #f8fafc;
  font-weight: 600;
  color: var(--muted);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .3px;
  padding: 6px 8px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}}
.tb td {{
  padding: 5px 8px;
  border-bottom: 1px solid #f1f5f9;
  word-break: break-word;
}}
.tb tr:last-child td {{ border-bottom: none }}
.sev-critical td:first-child {{ border-left: 3px solid #991b1b }}
.sev-high td:first-child {{ border-left: 3px solid var(--red) }}
.sev-medium td:first-child {{ border-left: 3px solid var(--amber) }}
.sev-low td:first-child {{ border-left: 3px solid var(--blue) }}
.sev-info td:first-child {{ border-left: 3px solid #94a3b8 }}
.t-fail td {{ background: #fef2f2 }}
.finding-title {{ font-weight: 600; font-size: 12px; margin-bottom: 1px }}
.finding-detail {{ font-size: 11px; color: var(--muted) }}
.model-tag {{
  display: inline-block;
  background: #eff6ff;
  color: var(--blue);
  font-size: 9px;
  padding: 0 5px;
  border-radius: 3px;
  margin-left: 4px;
  font-weight: 600;
}}
.tag {{
  display: inline-block;
  padding: 1px 7px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 700;
  color: #fff;
  white-space: nowrap;
}}
.tag-critical {{ background: #991b1b }}
.tag-high {{ background: var(--red) }}
.tag-medium {{ background: var(--amber) }}
.tag-low {{ background: var(--blue) }}
.tag-info {{ background: #94a3b8 }}
.cat {{
  display: inline-block;
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 9px;
  font-weight: 600;
  white-space: nowrap;
}}
.cat-security {{ background: #fef2f2; color: var(--red) }}
.cat-identity {{ background: #fffbeb; color: var(--amber) }}
.cat-quality {{ background: #eff6ff; color: var(--blue) }}
.cat-performance {{ background: #f0fdf4; color: var(--green) }}
.cat-model {{ background: #eff6ff; color: var(--blue) }}
.cat-general {{ background: #f1f5f9; color: var(--muted) }}
.s-ok {{ color: var(--green); font-weight: 700; font-size: 11px }}
.s-fail {{ color: var(--red); font-weight: 700; font-size: 11px }}
.s-refused {{ color: #94a3b8; font-weight: 700; font-size: 11px }}
.stream-tag {{
  display: inline-block;
  background: #dbeafe;
  color: var(--blue);
  font-size: 9px;
  padding: 0 3px;
  border-radius: 2px;
  margin-left: 3px;
  font-weight: 600;
}}
.test-name {{ font-weight: 500 }}
.n {{ text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums }}
.model-col {{ font-size: 11px; color: var(--muted); max-width: 100px; overflow: hidden; text-overflow: ellipsis }}
.rp {{ max-width: 180px; font-size: 11px; color: var(--muted) }}
.bt {{ display: inline-block; width: 30px; height: 3px; background: var(--border); border-radius: 2px; vertical-align: middle; margin-left: 3px }}
.bf {{ height: 3px; border-radius: 2px }}
.resp-preview {{
  display: block;
  max-height: 32px;
  overflow: hidden;
  line-height: 1.3;
  background: #f8fafc;
  padding: 2px 5px;
  border-radius: 3px;
  font-size: 11px;
}}
.r {{ font-size: 10px; color: var(--muted); display: block; margin-top: 1px }}
.no-issues {{ text-align:center; color:var(--green); padding:20px; font-weight:600; font-size:13px }}
.footer {{
  text-align: center;
  color: #94a3b8;
  font-size: 10px;
  margin-top: 8px;
  padding: 4px 0;
}}
@media (max-width: 640px) {{
  body {{ padding: 10px 8px }}
  .card {{ padding: 12px }}
  .summary-bar {{ gap: 10px; padding: 10px }}
  .risk-level {{ font-size: 15px; padding: 4px 10px }}
  .score-num {{ font-size: 22px }}
  .tb {{ font-size: 11px }}
  .tb th, .tb td {{ padding: 4px 5px }}
  .rp {{ max-width: 100px }}
  .meta-line {{ margin-left: 0; text-align: left; width: 100% }}
}}
@media print {{
  body {{ background: #fff; padding: 0; max-width: none }}
  .card {{ border: 1px solid #ddd; page-break-inside: avoid }}
}}
</style>
</head>
<body>

<div class="summary-bar">
  <span class="risk-level" style="background:{badge_color}">{risk_cn.get(risk, risk)}</span>
  <div>
    <div class="score-num" style="color:{score_color}">{score_val}</div>
    <div class="score-label">评分</div>
  </div>
  <div class="pass-info">
    <div class="pass-label">通过率</div>
    <div class="pass-value">{pass_rate} ({pass_rate_pct}%)</div>
    <div class="pass-bar-sm"><div class="pass-fill-sm" style="width:{pass_rate_pct}%"></div></div>
  </div>
  <div class="meta-line">
    <div class="url-text">{esc(base_url)}</div>
    <div>模型: {esc(model)} · {esc(sd)} · {int(result.duration_s)}s · {perf["avg_lat"]:.0f}ms · {perf["avg_tps"]} tok/s</div>
  </div>
</div>

<div class="card">
  <div class="stats-row">
    <span class="stat-pill stat-pill-high"><span class="stat-pill-num">{result.high_count}</span> 高危</span>
    <span class="stat-pill stat-pill-med"><span class="stat-pill-num">{result.med_count}</span> 中危</span>
    <span class="stat-pill stat-pill-low"><span class="stat-pill-num">{result.low_count}</span> 低危</span>
    <span class="stat-pill stat-pill-ok"><span class="stat-pill-num">{effective_ok}/{total}</span> 通过</span>
  </div>

  {rec_html}
</div>

<div class="card">
  <h2>关键问题 <span class="count">{len(high_med_findings)}</span></h2>
  {f'<table class="tb"><thead><tr><th style="width:50px">等级</th><th style="width:50px">类别</th><th>问题</th></tr></thead><tbody>{frows_high_med}</tbody></table>' if frows_high_med else '<div class="no-issues">✓ 无高危/中危问题</div>'}
  {f'<details><summary>低危/信息 ({len(low_info_findings)})</summary><table class="tb" style="margin-top:8px"><thead><tr><th style="width:50px">等级</th><th style="width:50px">类别</th><th>问题</th></tr></thead><tbody>{frows_low_info}</tbody></table></details>' if frows_low_info else ""}
</div>

<div class="card">
  <h2>失败测试 <span class="count">{fail_count}</span></h2>
  {f'<table class="tb"><thead><tr><th>项目</th><th style="width:42px">结果</th><th style="width:90px">延迟</th><th style="width:50px">tok/s</th><th>响应预览</th><th style="width:100px">返回模型</th></tr></thead><tbody>{rrows_fail}</tbody></table>' if rrows_fail else '<div class="no-issues" style="color:var(--green);padding:12px">✓ 所有测试通过</div>'}
  {f'<details><summary>通过测试 ({ok_count})</summary><table class="tb" style="margin-top:8px"><thead><tr><th>项目</th><th style="width:42px">结果</th><th style="width:90px">延迟</th><th style="width:50px">tok/s</th><th>响应预览</th><th style="width:100px">返回模型</th></tr></thead><tbody>{rrows_ok}</tbody></table></details>' if rrows_ok else ""}
</div>

<div class="footer">Relay Audit v{esc(result.version)} · {esc(sd)}</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════
# 报告保存
# ═══════════════════════════════════════════════════════════════


def save_report(result: ScanResult, output_path: str | None = None) -> str:
    if output_path is None or output_path == "auto":
        output_path = os.path.join(
            _reports_dir(), f"relay_report_{dt.datetime.now():%Y%m%d_%H%M%S}.html"
        )
    html = generate_html(result)
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _clean_old_reports(dir_path: str, days: int = 7) -> None:
    cutoff = dt.datetime.now().timestamp() - days * 86400
    try:
        for f in os.listdir(dir_path):
            if (f.startswith("relay_report_") and f.endswith(".html")) or (
                f.startswith("scan_") and f.endswith(".json")
            ):
                fp = os.path.join(dir_path, f)
                if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                    os.remove(fp)
    except Exception:
        import sys
        print("  [!] 清理旧报告失败", file=sys.stderr)

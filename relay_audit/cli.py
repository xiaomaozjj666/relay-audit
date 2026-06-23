"""命令行入口 + 报告生成 — 傻瓜式使用，只需 Key 和地址"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import html as htmlmod
import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import ChatResult, Finding, ModelInfo, REFUSAL_PATTERNS, ScanConfig, ScanResult, Severity, redact, short
from .scanner import fetch_models, run_scan

# 中文映射
CAT_CN = {"security": "安全", "identity": "身份", "quality": "质量", "performance": "性能", "model": "模型", "general": "通用"}
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}

# ── 工具函数 ──────────────────────────────────────────────────

def _key_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".relay_key")


def _load_key_from_file() -> str:
    kf = _key_path()
    if os.path.isfile(kf):
        try:
            with open(kf, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""


def _save_key_to_file(key: str) -> None:
    with open(_key_path(), "w", encoding="utf-8") as f:
        f.write(key)
    print(f"  [v] 已保存到 {_key_path()}")


def _delete_key_file() -> None:
    kf = _key_path()
    if os.path.isfile(kf):
        os.remove(kf)


def _ensure_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ── 模型自动选择 ──────────────────────────────────────────────

PREFERRED_ORDER = ["claude", "gpt", "gemini", "deepseek", "qwen", "kimi", "glm", "llama", "step", "mistral"]


def auto_select_model(model_ids: list[str], top_n: int = 1) -> list[str]:
    """从模型列表中智能选择最强的 N 个模型（不限品牌）"""
    import re
    router_keywords = ["auto", "router", "pool", "default", "free", "fallback"]
    candidates = [
        m for m in model_ids
        if not any(k in m.lower() for k in router_keywords)
        and not m.startswith("text-embedding")
        and not m.startswith("tts-")
    ]
    if not candidates:
        candidates = model_ids

    def version_score(name: str) -> tuple:
        """返回 (主版本, 次版本, 其他数字...) 用于比较大小"""
        nums = re.findall(r'(\d+)\.?(\d*)?', name)
        parts = []
        for a, b in nums:
            parts.append(int(a))
            if b:
                parts.append(int(b))
        return tuple(parts) if parts else (0,)

    lower = [m.lower() for m in candidates]

    # 第一步：每个模型族内选版本最高的
    per_family: list[tuple[str, tuple]] = []
    for pref in PREFERRED_ORDER:
        matches = [(candidates[i], version_score(candidates[i])) for i, l in enumerate(lower) if pref in l]
        if matches:
            matches.sort(key=lambda x: x[1], reverse=True)
            per_family.append(matches[0])

    # 第二步：如果家族数不够 top_n，再从已有家族里补充次强的
    if len(per_family) < top_n:
        used = {m for m, _ in per_family}
        all_scored = [(candidates[i], version_score(candidates[i])) for i in range(len(candidates))]
        all_scored.sort(key=lambda x: x[1], reverse=True)
        for name, score in all_scored:
            if name not in used:
                per_family.append((name, score))
                used.add(name)
                if len(per_family) >= top_n:
                    break

    selected = [name for name, _ in per_family]
    return selected[:top_n] if selected else (candidates[:1] if candidates else [])


def show_models_table(model_ids: list[str]) -> None:
    """在终端展示模型列表"""
    print(f"\n  该 API 共有 {len(model_ids)} 个模型：")
    # 分组展示
    families: dict[str, list[str]] = {}
    for m in model_ids:
        key = "其他"
        m_lower = m.lower()
        for fam in ["claude", "gpt", "gemini", "deepseek", "qwen", "llama",
                     "mistral", "glm", "phi", "cohere", "yi", "gemma",
                     "minicpm", "kimi", "doubao", "ernie", "hunyuan",
                     "baichuan", "step", "spark"]:
            if fam in m_lower:
                key = fam
                break
        families.setdefault(key, []).append(m)

    for fam in ["claude", "gpt", "gemini", "deepseek", "qwen", "llama",
                "mistral", "glm", "phi", "cohere", "yi", "gemma",
                "minicpm", "kimi", "doubao", "ernie", "hunyuan",
                "baichuan", "step", "spark"]:
        if fam in families:
            models = families.pop(fam)
            print(f"  [{fam}] {', '.join(models[:8])}")
            if len(models) > 8:
                print(f"         ... 还有 {len(models)-8} 个")

    if families:
        for fam, models in families.items():
            print(f"  [{fam}] {', '.join(models[:5])}")
            if len(models) > 5:
                print(f"         ... 还有 {len(models)-5} 个")


# ── 扫描执行 ──────────────────────────────────────────────────

def _build_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        base_url=args.base_url,
        model=args.model or "",
        api_key_env=args.api_key_env or "RELAY_API_KEY",
        timeout=args.timeout or 60,
        samples=args.samples or 3,
        compare=[m for m in (args.compare or []) if m],
        quick=bool(args.quick),
        stream=bool(args.stream),
        skip_safety=bool(args.skip_safety),
        json_output=bool(args.json),
        output=args.output,
        no_html=bool(args.no_html),
        config_file=args.config,
    )


def execute_scan(config: ScanConfig) -> tuple[int, str, ScanResult | None]:
    """加载 key 并执行扫描，返回 (exit_code, report_path)"""
    key = os.environ.get(config.api_key_env, "") or _load_key_from_file()
    if not key:
        print("错误: API Key 未设置（通过环境变量或 --key）", file=sys.stderr)
        return 2, "", None

    os.environ[config.api_key_env] = key

    # 如果没指定模型，自动获取列表并选一个
    if not config.model:
        print("  [i] 未指定模型，正在获取模型列表...")
        ids = asyncio.run(fetch_models(config.base_url, key, config.timeout))
        if not ids:
            print("  [x] 无法获取模型列表，请用 --model 手动指定", file=sys.stderr)
            return 2, "", None
        selected = auto_select_model(ids)
        if not selected:
            print("  [x] 无法自动选择模型，请用 --model 手动指定", file=sys.stderr)
            return 2, "", None
        config.model = selected[0]
        print(f"  [i] 自动选择模型: {selected[0]}")

    result = asyncio.run(run_scan(config))

    # 先保存报告（确保即使终端输出出错也有报告）
    report_path = ""
    if not config.no_html:
        try:
            report_path = save_report(result, config.output)
        except Exception:
            pass

    if config.json_output:
        print_json(result)
    else:
        try:
            print_terminal(result)
        except Exception as e:
            print(f"  [i] 终端输出异常: {e}")
            _print_plain(result)

    # 打印报告路径并自动打开
    if report_path:
        print(f"  报告: {report_path}")
        try:
            webbrowser.open(Path(report_path).as_uri())
        except Exception:
            pass

    return 1 if result.high_count else 0, report_path, result


# ── 展示模型列表 ─────────────────────────────────────────────

def cmd_list_models(args: argparse.Namespace) -> int:
    """只展示模型列表，不跑测试"""
    key = args.key or os.environ.get(args.api_key_env or "RELAY_API_KEY", "") or _load_key_from_file()
    if not key:
        print("错误: API Key 未设置", file=sys.stderr)
        return 2
    ids = asyncio.run(fetch_models(args.base_url, key, args.timeout or 60))
    if not ids:
        print("  [x] 无法获取模型列表", file=sys.stderr)
        return 1
    show_models_table(ids)
    return 0


# ── 交互模式 ──────────────────────────────────────────────────

def interactive() -> int:
    """交互模式 — 只需 Key 和地址，全自动检测"""
    os.system("")  # type: ignore

    while True:
        print()
        print("  +------------------------------------------+")
        print("  |  Relay Audit - 中转 API 检测工具 v" + __version__ + "  |")
        print("  +------------------------------------------+")
        print()

        key = input("  [1/3] API Key > ").strip()
        while not key:
            print("  [x] API Key 不能为空")
            key = input("  [1/3] API Key > ").strip()
        os.environ["RELAY_API_KEY"] = key

        url = input("  [2/3] API 地址 > ").strip()
        while not url:
            print("  [x] 地址不能为空")
            url = input("  [2/3] API 地址 > ").strip()

        # 3. 拉模型列表
        print(f"  [3/3] 正在获取模型列表...")
        ids = asyncio.run(fetch_models(url, key, 30))
        if not ids:
            print("  [x] 无法连接，请检查地址和 Key 是否正确")
            retry = input("  重试？(y/N): ").strip().lower()
            if retry in ("y", "yes"):
                continue
            break

        show_models_table(ids)

        # 自动选择最强 3 个模型
        models_to_test = auto_select_model(ids, top_n=3)
        print(f"\n  自动选择 {len(models_to_test)} 个最强模型: {', '.join(models_to_test)}")

        # 全面检测，对每个模型执行扫描（不生成报告）
        all_findings: list[Finding] = []
        all_results_list: list[ChatResult] = []
        total_duration = 0.0
        for i, model in enumerate(models_to_test):
            print(f"\n  [{i+1}/{len(models_to_test)}] 测试模型: {model}")
            config = ScanConfig(base_url=url, model=model, no_html=True)
            ec, _, scan_result = execute_scan(config)
            if scan_result:
                for f in scan_result.findings:
                    f.model_name = model
                all_findings.extend(scan_result.findings)
                all_results_list.extend(scan_result.results)
                total_duration += scan_result.duration_s
            if ec:
                print(f"  [!] {model}: 发现 {ec} 个高危问题")
            else:
                print(f"  [OK] {model}: 未发现高危问题")

        # 生成一份综合报告
        try:
            final_config = ScanConfig(base_url=url, model=", ".join(models_to_test))
            model_infos = [ModelInfo(id=m) for m in ids]
            final_result = ScanResult(
                config=final_config,
                findings=all_findings,
                results=all_results_list,
                models=model_infos,
                started_at=dt.datetime.now(dt.UTC).isoformat(),
                duration_s=total_duration,
            )
            report_path = save_report(final_result)
            print(f"  报告: {report_path}")
            try:
                webbrowser.open(Path(report_path).as_uri())
            except Exception:
                pass
        except Exception as e:
            print(f"  [x] 报告失败: {e}")

        again = input("\n  检测另一个？(y/N): ").strip().lower()
        if again not in ("y", "yes"):
            break

    print("  再见。")
    return 0


# ── 配置加载 ──────────────────────────────────────────────────

def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── CLI ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Relay Audit - OpenAI-compatible 中转 API 检测工具。只需提供 Key 和地址即可使用。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  # 最简用法（自动选模型）
  set RELAY_API_KEY=sk-xxx
  relay-audit --base-url https://api.example.com

  # 指定模型
  relay-audit --base-url https://api.example.com --model claude-opus-4-6

  # 只看模型列表
  relay-audit --base-url https://api.example.com --models

  # 快速模式
  relay-audit --quick --base-url https://api.example.com

  # 无参数 = 交互模式
  relay-audit
""",
    )
    ap.add_argument("--base-url", help="API 端点地址")
    ap.add_argument("--model", default="", help="检测模型名（不填则自动选择）")
    ap.add_argument("--key", help="API Key（优先于环境变量）")
    ap.add_argument("--api-key-env", default="RELAY_API_KEY", help="API Key 环境变量名 (默认 RELAY_API_KEY)")
    ap.add_argument("--timeout", type=int, default=60, help="请求超时秒数 (默认 60)")
    ap.add_argument("--samples", type=int, default=3, help="稳定性采样次数 (默认 3)")
    ap.add_argument("--compare", action="append", default=[], help="对比模型（可多次使用）")
    ap.add_argument("--quick", action="store_true", help="快速模式（跳过安全测试）")
    ap.add_argument("--stream", action="store_true", help="启用流式响应测试")
    ap.add_argument("--json", action="store_true", help="输出 JSON 格式结果")
    ap.add_argument("--output", help="报告输出路径")
    ap.add_argument("--no-html", action="store_true", help="不生成 HTML 报告")
    ap.add_argument("--skip-safety", action="store_true", help="跳过安全测试")
    ap.add_argument("--config", help="JSON 配置文件路径")
    # 展示模型列表
    ap.add_argument("--models", "--list-models", action="store_true", dest="list_models",
                    help="只展示可用模型列表，不跑测试")
    return ap


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()

    if argv is None:
        argv = sys.argv[1:]

    ap = build_parser()

    # 无参数 → 交互模式
    if not argv:
        return interactive()

    args = ap.parse_args(argv)

    # 配置文件加载
    if args.config:
        cfg = load_config(args.config)
        for key, default in [
            ("base_url", None), ("model", ""), ("timeout", 60),
            ("samples", 3), ("compare", []), ("quick", False),
            ("stream", False), ("json", False), ("output", None),
            ("no_html", False), ("skip_safety", False), ("api_key_env", "RELAY_API_KEY"),
        ]:
            if key in cfg and getattr(args, key, None) in (None, "", [], False, default):
                setattr(args, key, cfg[key])

    if not args.base_url:
        ap.error("--base-url 是必填参数")

    # 如果有 --key 参数，设到环境变量
    if args.key:
        os.environ[args.api_key_env or "RELAY_API_KEY"] = args.key

    # --models 模式：只展示列表
    if args.list_models:
        return cmd_list_models(args)

    config = _build_config(args)
    ec, _, _ = execute_scan(config)
    return ec


# ═══════════════════════════════════════════════════════════════
# 报告生成 — 终端 / JSON / HTML
# ═══════════════════════════════════════════════════════════════

def print_terminal(result: ScanResult) -> None:
    """终端输出（使用 Rich 彩色，降级到纯文本）"""
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
    # 底部一行总结
    ok = [r for r in result.results if r.ok]
    lats = [r.latency_ms for r in ok]
    avg = sum(lats) / len(lats) if lats else 0
    tps = [r.tokens_per_second for r in ok if r.tokens_per_second]
    avg_tps = f"{sum(tps)/len(tps):.1f}" if tps else "-"
    print(f"  {'-'*40}")
    print(f"  耗时 {result.duration_s:.0f}s | 测试 {len(result.results)} 项 | "
          f"高危 {result.high_count} 中危 {result.med_count} 低危 {result.low_count} | "
          f"延迟 {avg:.0f}ms | {avg_tps} tok/s  | 风险 {result.risk_level}")


def _print_rich(result: ScanResult) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
    safety_names = {"Prompt隔离", "拒绝-破坏性", "拒绝-窃取", "拒绝-勒索", "拒绝-反向Shell", "拒绝-SQL注入",
                    "Cookie 窃取拒答", "破坏代码拒答", "数据外传拒答",
                    "恶意JS窃取Cookie", "勒索软件", "反向Shell", "键盘记录器",
                    "SQL注入", "DDoS脚本", "钓鱼页面", "提示泄露"}
    ok = [r for r in result.results if r.ok]
    # 安全测试超时/限流也算通过
    effective_ok = len(ok) + sum(
        1 for r in result.results
        if not r.ok and r.name in safety_names and r.status in (0, 429, 500, 502, 503, 504)
    )
    lats = [r.latency_ms for r in ok]
    avg = sum(lats) / len(lats) if lats else 0
    mx = max(lats) if lats else 0
    tps = [r.tokens_per_second for r in ok if r.tokens_per_second]
    avg_tps = sum(tps) / len(tps) if tps else 0
    risk_st = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}.get(result.risk_level, "bold white")

    # 头部概要
    console.print()
    console.print(Panel(
        f"[bold]{result.config.base_url}[/]\n"
        f"模型: [cyan]{result.config.model}[/]  |  "
        f"[{risk_st}]风险 {result.risk_level}[/]  |  "
        f"耗时 {result.duration_s:.0f}s  |  测试 {len(result.results)} 项",
        title="[bold]Relay Audit[/]", border_style="blue",
    ))

    # 统计卡片
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

    # 检测发现
    if result.findings:
        t = Table(box=box.ROUNDED, title="检测发现", title_style="bold")
        t.add_column("", width=6)
        t.add_column("类别", width=8)
        t.add_column("问题", ratio=3)
        t.add_column("详情", ratio=2)
        colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
        for f in result.findings:
            c = colors.get(f.severity.value, "white")
            sev = SEV_CN.get(f.severity.value, f.severity.value)
            cat = CAT_CN.get(f.category, f.category)
            detail = short(f.detail, 60)
            reason = f"\n[dim italic]{f.reason}[/]" if f.reason else ""
            t.add_row(f"[{c}]{sev}[/]", f"[dim]{cat}[/]", f"{f.title}{reason}", f"[dim]{detail}[/]")
        console.print(t)
    else:
        console.print("[green]✓[/] 未发现异常")

    # 测试明细
    rt = Table(box=box.SIMPLE, title="测试明细", title_style="bold")
    rt.add_column("项目", min_width=14)
    rt.add_column("结果", width=6, justify="center")
    rt.add_column("延迟", width=8, justify="right")
    rt.add_column("tok/s", width=7, justify="right")
    rt.add_column("请求模型", max_width=20)
    rt.add_column("返回模型", max_width=20)

    for r in result.results:
        refused = bool(REFUSAL_PATTERNS.search(r.content)) if r.content else False
        is_safety = r.name in safety_names
        # 安全测试超时/限流 → 视为拒绝
        if is_safety and not r.ok and r.status in (0, 429, 500, 502, 503, 504):
            ok_cls = "[yellow]拒[/]"
        elif refused:
            ok_cls = "[green]✓[/]"  # 明确拒绝 → 通过
        elif r.ok:
            ok_cls = "[green]✓[/]"
        else:
            ok_cls = "[red]✗[/]"
        tps_s = f"{r.tokens_per_second:.1f}" if r.tokens_per_second else "-"
        lat_color = "red" if r.latency_ms > 3000 else "yellow" if r.latency_ms > 1000 else ""
        lat_s = f"[{lat_color}]{r.latency_ms}ms[/]" if lat_color else f"{r.latency_ms}ms"
        st = " [dim][流][/]" if r.streaming else ""
        rt.add_row(f"{r.name}{st}", ok_cls, lat_s, tps_s,
                   f"[dim]{r.model_req}[/]", f"[dim]{r.model_ret or '-'}[/]")
    console.print(rt)

    # 底部性能
    console.print(f"  [dim]延迟 avg={avg:.0f}ms max={mx}ms  |  {avg_tps:.1f} tok/s  |  "
                  f"通过 {effective_ok}/{len(result.results)}[/]")
    console.print()


def print_json(result: ScanResult) -> None:
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


def esc(text: str) -> str:
    return htmlmod.escape(redact(str(text)))


def _score_bars(findings: list[Finding]) -> str:
    """生成模型评分卡片（已去重，同一问题只扣一次分）"""
    seen: set[tuple[str, str]] = set()
    model_data: dict[str, dict] = {}
    for f in findings:
        model_key = f.model_name or "(default)"
        key = (model_key, f.title)
        if key in seen:
            continue
        seen.add(key)
        if model_key not in model_data:
            model_data[model_key] = {"high": 0, "med": 0, "low": 0}
        sev = f.severity.value
        if sev in ("critical", "high"):
            model_data[model_key]["high"] += 1
        elif sev == "medium":
            model_data[model_key]["med"] += 1
        elif sev in ("low", "info"):
            model_data[model_key]["low"] += 1

    if not model_data:
        return '<p style="color:#999;text-align:center;padding:20px 0">无评分数据</p>'

    def calc_score(h: int, m: int, l: int) -> tuple[int, str]:
        score = 100 - h * 15 - m * 5 - l * 2
        score = max(10, score)
        if score >= 90: color = "#27ae60"
        elif score >= 70: color = "#f39c12"
        elif score >= 50: color = "#e67e22"
        else: color = "#e74c3c"
        return score, color

    cards = ""
    for model, data in sorted(model_data.items(), key=lambda x: -(
        x[1]["high"] * 100 + x[1]["med"] * 10
    )):
        s, c = calc_score(data["high"], data["med"], data["low"])
        issues = []
        if data["high"]: issues.append(f'<span class="tag tag-high">{data["high"]}高危</span>')
        if data["med"]: issues.append(f'<span class="tag tag-medium">{data["med"]}中危</span>')
        if data["low"]: issues.append(f'<span class="tag tag-low">{data["low"]}低危</span>')
        tags = " ".join(issues) if issues else '<span style="color:#27ae60">✓ 无问题</span>'
        cards += (
            f'<div class="score-card">'
            f'<div class="score-grade" style="color:{c}">{s}</div>'
            f'<div class="score-label">{esc(model)}</div>'
            f'<div class="score-bar"><div class="score-fill" style="width:{s}%;background:{c}"></div></div>'
            f'<div style="margin-top:8px;font-size:11px">{tags}</div>'
            f'</div>'
        )

    return f'<div class="score-grid">{cards}</div>'


def _cat_counts(findings: list[Finding]) -> dict[str, int]:
    c: dict[str, int] = {}
    for f in findings:
        c[f.category] = c.get(f.category, 0) + 1
    return c


def _perf_stats(result: ScanResult) -> dict[str, Any]:
    ok = [r for r in result.results if r.ok]
    if not ok:
        return {"avg_lat": 0, "max_lat": 0, "avg_tps": 0, "ok_count": 0}
    l = [r.latency_ms for r in ok]
    t = [r.tokens_per_second for r in ok if r.tokens_per_second]
    return {"avg_lat": round(sum(l) / len(l), 0), "max_lat": max(l),
            "avg_tps": round(sum(t) / len(t), 1) if t else 0, "ok_count": len(ok)}


def _generate_recommendations(result: ScanResult) -> str:
    """根据检测结果生成建议"""
    recs: list[str] = []
    cats = {f.category for f in result.findings}

    if result.high_count:
        recs.append("存在高危问题，建议立即排查中转服务的安全性和模型真实性")
    if "identity" in cats:
        recs.append("检测到模型身份异常，中转可能替换了实际使用的模型，建议对比官方 API 输出")
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

    items = "".join(f'<li>{esc(r)}</li>' for r in recs)
    return f'<ul class="rec-list">{items}</ul>'


def _response_preview(content: str, max_len: int = 200) -> str:
    """生成响应内容预览 HTML"""
    if not content:
        return '<span class="empty">无响应</span>'
    preview = redact(content).replace("\r", "").replace("\n", " ").strip()
    if len(preview) > max_len:
        preview = preview[:max_len] + "…"
    return f'<span class="resp-preview">{esc(preview)}</span>'


def generate_html(result: ScanResult) -> str:
    """综合式报告 — 单栏、清晰、精简"""
    base_url, model, risk = result.config.base_url, result.config.model, result.risk_level
    perf = _perf_stats(result)
    ok_lats = [r.latency_ms for r in result.results if r.ok]
    max_lat = max(ok_lats) if ok_lats else 1

    risk_cn = {"HIGH": "高风险", "MEDIUM": "中风险", "LOW": "低风险"}
    sev_cn = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
    cat_cn = {"security": "安全", "identity": "身份", "quality": "质量", "performance": "性能", "model": "模型", "general": "通用"}

    # ── 安全测试集合 + 有效通过数 ──
    safety_names = {"Prompt隔离", "拒绝-破坏性", "拒绝-窃取", "拒绝-勒索", "拒绝-反向Shell", "拒绝-SQL注入",
                    "Cookie 窃取拒答", "破坏代码拒答", "数据外传拒答",
                    "恶意JS窃取Cookie", "勒索软件", "反向Shell", "键盘记录器",
                    "SQL注入", "DDoS脚本", "钓鱼页面", "提示泄露"}
    effective_ok = sum(1 for r in result.results if r.ok or (
        r.name in safety_names and r.status in (0, 429, 500, 502, 503, 504)
    ))
    total = len(result.results)
    pass_rate = f"{effective_ok}/{total}"

    # ── 评分 ──
    score_html = _score_bars(result.findings)

    # ── 建议 ──
    recs: list[str] = []
    if result.high_count: recs.append("⚠ 存在高危问题，建议排查")
    if {f.category for f in result.findings} & {"identity"}: recs.append("⚠ 模型身份异常")
    if {f.category for f in result.findings} & {"security"}: recs.append("⚠ 安全风险")
    if result.risk_level == "LOW" and not result.high_count: recs.append("✓ 整体正常")
    if not recs: recs.append("✓ 未发现异常")
    rec_html = " · ".join(recs)

    # ── 发现 ──
    frows = ""
    for f in result.findings:
        sc = f.severity.value
        sv = sev_cn.get(sc, sc)
        cc = cat_cn.get(f.category, f.category)
        reason = f" <span class='r'>{esc(f.reason)}</span>" if f.reason else ""
        frows += f'<tr class="sev-{sc}"><td><span class="tag tag-{sc}">{sv}</span></td><td><span class="cat cat-{esc(f.category)}">{cc}</span> {esc(f.title)}{reason}</td></tr>\n'

    # ── 测试 ──
    rrows = ""
    for r in result.results:
        refused = bool(REFUSAL_PATTERNS.search(r.content)) if r.content else False
        is_safety = r.name in safety_names
        st = " [流]" if r.streaming else ""
        pct = min(100, int(r.latency_ms / max_lat * 100)) if r.ok and max_lat else 0
        bc = "#e74c3c" if r.latency_ms > 3000 else "#f39c12" if r.latency_ms > 1000 else "#27ae60" if r.ok else "#484f58"
        bar = f'<div class="bt"><div class="bf" style="width:{pct}%;background:{bc}"></div></div>' if r.ok else ""
        if is_safety and not r.ok and r.status in (0, 429, 500, 502, 503, 504):
            s_tag, s_cls, row_cls = "拒绝", "refused", "ok"
        elif refused:
            s_tag, s_cls, row_cls = "拒绝", "refused", "ok"
        elif r.ok:
            s_tag, s_cls, row_cls = "通过", "ok", "ok"
        else:
            s_tag, s_cls, row_cls = "失败", "fail", "fail"
        preview = _response_preview(r.content, 60)
        tps = f"{r.tokens_per_second:.1f}" if r.tokens_per_second else "-"
        rrows += f'<tr class="t-{row_cls}"><td>{esc(r.name)}{st}</td><td><span class="s-{s_cls}">{s_tag}</span></td><td class="n">{r.latency_ms}ms{bar}</td><td class="n">{tps}</td><td class="rp">{preview}</td></tr>\n'

    sd = result.started_at[:19].replace("T", " ") if result.started_at else "-"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Relay Audit | {esc(base_url)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#f0f2f5;font:13px/1.5 -apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:#1a1a2e;padding:20px;max-width:900px;margin:auto}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 8px rgba(0,0,0,.05);padding:18px;margin-bottom:14px}}
h1{{font-size:17px;font-weight:700}}.meta{{color:#888;font-size:12px;margin-top:3px;word-break:break-all}}
h2{{font-size:13px;font-weight:600;color:#555;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #f0f0f0}}
.badge{{display:inline-block;padding:3px 14px;border-radius:16px;font-weight:700;font-size:13px;color:#fff}}
.badge-HIGH{{background:linear-gradient(135deg,#e74c3c,#c0392b)}}.badge-MEDIUM{{background:linear-gradient(135deg,#f39c12,#d68910)}}.badge-LOW{{background:linear-gradient(135deg,#27ae60,#1e8449)}}
.stats{{display:flex;gap:14px;margin:10px 0;flex-wrap:wrap}}.stat{{text-align:center;min-width:55px}}.stat-n{{font-size:22px;font-weight:800;line-height:1}}.stat-l{{font-size:10px;color:#999}}
.n-red{{color:#e74c3c}}.n-yellow{{color:#f39c12}}.n-blue{{color:#3498db}}.n-gray{{color:#666}}
.pass-rate{{font-size:14px;font-weight:700;color:#27ae60;margin:8px 0}}
.rec{{font-size:12px;color:#555;margin:6px 0}}
.score-row{{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0}}
.score-grid{{display:flex;gap:10px;flex-wrap:wrap}}
.score-card{{background:#f8f9fc;border-radius:8px;padding:10px;text-align:center;min-width:90px}}
.score-grade{{font-size:32px;font-weight:800;line-height:1}}.score-label{{font-size:10px;color:#999;margin-top:2px;word-break:break-all}}
.score-bar{{height:3px;background:#e8e8e8;border-radius:2px;overflow:hidden;margin-top:3px}}.score-fill{{height:3px;border-radius:2px}}
.tb{{width:100%;border-collapse:collapse;font-size:12px}}
.tb th{{background:#f8f9fc;font-weight:600;color:#888;font-size:10px;text-transform:uppercase;letter-spacing:.3px;padding:5px 8px;text-align:left;border-bottom:1px solid #eee;white-space:nowrap}}
.tb td{{padding:4px 8px;border-bottom:1px solid #f5f5f5;color:#333;word-break:break-word}}.tb tr:last-child td{{border-bottom:none}}.tb tr:hover td{{background:#fafbfc}}
.sev-critical td:first-child{{border-left:2px solid #c0392b}}.sev-high td:first-child{{border-left:2px solid #e74c3c}}.sev-medium td:first-child{{border-left:2px solid #f39c12}}.sev-low td:first-child{{border-left:2px solid #3498db}}.sev-info td:first-child{{border-left:2px solid #95a5a6}}
.t-fail td{{background:#fef8f8}}.t-fail:hover td{{background:#fdf0f0}}
.s-ok{{color:#27ae60;font-weight:600;font-size:11px}}.s-fail{{color:#e74c3c;font-weight:600;font-size:11px}}.s-refused{{color:#8b949e;font-weight:600;font-size:11px}}
.tag{{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;font-weight:600;color:#fff}}
.tag-critical{{background:#c0392b}}.tag-high{{background:#e74c3c}}.tag-medium{{background:#f39c12}}.tag-low{{background:#3498db}}.tag-info{{background:#95a5a6}}
.cat{{display:inline-block;padding:1px 5px;border-radius:5px;font-size:9px;font-weight:600;margin-right:2px}}
.cat-security{{background:#fde8e8;color:#e74c3c}}.cat-identity{{background:#fef3e2;color:#f39c12}}.cat-quality{{background:#e8f4fd;color:#3498db}}.cat-performance{{background:#e8f8ee;color:#27ae60}}.cat-model{{background:#e8f0fa;color:#5b7fa5}}.cat-general{{background:#f5f5f5;color:#888}}
.r{{font-size:10px;color:#999}}.mono{{font-family:'SF Mono','Consolas',monospace;font-size:11px;color:#666}}
.n{{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}}.rp{{max-width:180px;font-size:11px;color:#666}}
.bt{{display:inline-block;width:36px;height:4px;background:#eee;border-radius:2px;vertical-align:middle;margin-left:4px}}.bf{{height:4px;border-radius:2px}}
.resp-preview{{display:block;max-height:36px;overflow:hidden;line-height:1.3;background:#f8f9fc;padding:2px 5px;border-radius:3px;border:1px solid #eef0f3}}.empty{{color:#ccc;font-style:italic;font-size:11px}}
.footer{{text-align:center;color:#bbb;font-size:10px;margin-top:10px;padding:6px 0}}
@media(max-width:600px){{body{{padding:10px}}.card{{padding:12px}}.stats{{gap:10px}}}}
</style>
</head>
<body>

<div class="card">
  <h1>🔍 中转 API 检测报告</h1>
  <div class="meta">{esc(base_url)} · {esc(model)} · {esc(sd)}</div>
  <div class="stats">
    <div class="stat"><div class="stat-n"><span class="badge badge-{risk}">{risk_cn.get(risk,risk)}</span></div></div>
    <div class="stat"><div class="stat-n n-red">{result.high_count}</div><div class="stat-l">高危</div></div>
    <div class="stat"><div class="stat-n n-yellow">{result.med_count}</div><div class="stat-l">中危</div></div>
    <div class="stat"><div class="stat-n n-blue">{result.low_count}</div><div class="stat-l">低危</div></div>
    <div class="stat"><div class="stat-n">{perf["avg_lat"]:.0f}ms</div><div class="stat-l">延迟</div></div>
    <div class="stat"><div class="stat-n">{perf["avg_tps"]}</div><div class="stat-l">tok/s</div></div>
    <div class="stat"><div class="stat-n">{int(result.duration_s)}s</div><div class="stat-l">耗时</div></div>
  </div>
  <div class="pass-rate">通过率 {pass_rate}</div>
  <div class="rec">{rec_html}</div>
  <div class="score-row">{score_html}</div>
</div>

<div class="card">
  <h2>🔎 检测发现 ({len(result.findings)})</h2>
  <table class="tb">
    <thead><tr><th style="width:50px">等级</th><th>问题</th></tr></thead>
    <tbody>{frows if frows else '<tr><td colspan="2" style="text-align:center;color:#999;padding:10px">✅ 未发现异常</td></tr>'}</tbody>
  </table>
</div>

<div class="card">
  <h2>📋 测试明细 ({total})</h2>
  <table class="tb">
    <thead><tr><th>项目</th><th style="width:45px">结果</th><th style="width:100px">延迟</th><th style="width:50px">tok/s</th><th>响应</th></tr></thead>
    <tbody>{rrows}</tbody>
  </table>
</div>

<div class="footer">Relay Audit v{esc(result.version)} · {esc(sd)}</div>
</body>
</html>"""
# ═══════════════════════════════════════════════════════════════
# 报告保存
# ═══════════════════════════════════════════════════════════════

def _project_dir() -> str:
    """获取脚本所在目录"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _reports_dir() -> str:
    """获取报告存放目录"""
    d = os.path.join(_project_dir(), "reports")
    os.makedirs(d, exist_ok=True)
    _clean_old_reports(d, days=7)
    return d


def save_report(result: ScanResult, output_path: str | None = None) -> str:
    if output_path is None or output_path == "auto":
        output_path = os.path.join(_reports_dir(), f"relay_report_{dt.datetime.now():%Y%m%d_%H%M%S}.html")
    html = generate_html(result)
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _clean_old_reports(dir_path: str, days: int = 7) -> None:
    """清理指定目录下 N 天前的 relay_report 文件"""
    cutoff = dt.datetime.now().timestamp() - days * 86400
    try:
        for f in os.listdir(dir_path):
            if f.startswith("relay_report_") and f.endswith(".html"):
                fp = os.path.join(dir_path, f)
                if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                    os.remove(fp)
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())

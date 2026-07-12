"""命令行入口 + 交互模式 — 只需 Key 和地址"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Any

from . import __version__
from .models import ChatResult, Finding, ModelInfo, ScanConfig, ScanResult
from .scanner import fetch_models, run_scan
from .reporter import print_terminal, print_json, save_report


# ── 工具函数 ──────────────────────────────────────────────────


def _key_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".relay_key")


def _load_key_from_file() -> str:
    kf = _key_path()
    if os.path.isfile(kf):
        try:
            with open(kf, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            pass
    return ""


def _save_key_to_file(key: str) -> None:
    kf = _key_path()
    if sys.platform == "win32":
        import stat

        with open(kf, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            import subprocess

            subprocess.run(
                ["icacls", kf, "/inheritance:r", "/grant:r", f"{os.getlogin()}:F"],
                capture_output=True,
                check=False,
            )
        except Exception:
            try:
                os.chmod(kf, stat.S_IREAD | stat.S_IWRITE)
            except Exception:
                pass
    else:
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
    print(f"  [v] 已保存到 {kf}")


def _delete_key_file() -> None:
    kf = _key_path()
    if os.path.isfile(kf):
        os.remove(kf)


def _ensure_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


# ── 模型自动选择 ──────────────────────────────────────────────

PREFERRED_ORDER = [
    "claude",
    "gpt",
    "gemini",
    "deepseek",
    "qwen",
    "kimi",
    "glm",
    "llama",
    "step",
    "mistral",
]

MODEL_FAMILIES = [
    "claude",
    "gpt",
    "gemini",
    "deepseek",
    "qwen",
    "llama",
    "mistral",
    "glm",
    "phi",
    "cohere",
    "yi",
    "gemma",
    "minicpm",
    "kimi",
    "doubao",
    "ernie",
    "hunyuan",
    "baichuan",
    "step",
    "spark",
]


def auto_select_model(model_ids: list[str], top_n: int = 1) -> list[str]:
    """从模型列表中智能选择最强的 N 个模型"""
    import re

    router_keywords = ["auto", "router", "pool", "default", "free", "fallback"]
    candidates = [
        m
        for m in model_ids
        if not any(k in m.lower() for k in router_keywords)
        and not m.startswith("text-embedding")
        and not m.startswith("tts-")
    ]
    if not candidates:
        candidates = model_ids

    def version_score(name: str) -> tuple:
        nums = re.findall(r"(\d+)\.?(\d*)?", name)
        parts = []
        for a, b in nums:
            parts.append(int(a))
            if b:
                parts.append(int(b))
        return tuple(parts) if parts else (0,)

    lower = [m.lower() for m in candidates]

    per_family: list[tuple[str, tuple]] = []
    for pref in PREFERRED_ORDER:
        matches = [
            (candidates[i], version_score(candidates[i]))
            for i, lw in enumerate(lower)
            if pref in lw
        ]
        if matches:
            matches.sort(key=lambda x: x[1], reverse=True)
            per_family.append(matches[0])

    if len(per_family) < top_n:
        used = {m for m, _ in per_family}
        all_scored = [
            (candidates[i], version_score(candidates[i]))
            for i in range(len(candidates))
        ]
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
    families: dict[str, list[str]] = {}
    for m in model_ids:
        key = "其他"
        m_lower = m.lower()
        for fam in MODEL_FAMILIES:
            if fam in m_lower:
                key = fam
                break
        families.setdefault(key, []).append(m)

    for fam in MODEL_FAMILIES:
        if fam in families:
            models = families.pop(fam)
            print(f"  [{fam}] {', '.join(models[:8])}")
            if len(models) > 8:
                print(f"         ... 还有 {len(models) - 8} 个")

    if families:
        for fam, models in families.items():
            print(f"  [{fam}] {', '.join(models[:5])}")
            if len(models) > 5:
                print(f"         ... 还有 {len(models) - 5} 个")


# ── 扫描执行 ──────────────────────────────────────────────────


def _build_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        base_url=args.base_url,
        model=args.model or "",
        api_key_env=args.api_key_env or "RELAY_API_KEY",
        timeout=args.timeout or 60,
        samples=args.samples or 2,
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
    """加载 key 并执行扫描"""
    key = os.environ.get(config.api_key_env, "") or _load_key_from_file()
    if not key:
        print("错误: API Key 未设置（通过环境变量或 --key）", file=sys.stderr)
        return 2, "", None

    os.environ[config.api_key_env] = key

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

    # 保存 JSON 结果
    try:
        from .serve import persist_result

        persist_result(result, config.base_url)
    except Exception as e:
        print(f"  [w] JSON 结果保存失败: {e}", file=sys.stderr)

    report_path = ""
    if not config.no_html:
        try:
            report_path = save_report(result, config.output)
        except Exception as _rpt_err:
            print(f"  [w] 报告保存失败: {_rpt_err}", file=sys.stderr)

    if config.json_output:
        print_json(result)
    else:
        try:
            print_terminal(result)
        except Exception as e:
            print(f"  [i] 终端输出异常: {e}")

    if report_path:
        print(f"  报告: {report_path}")
        try:
            webbrowser.open(Path(report_path).as_uri())
        except Exception:
            pass

    return 1 if result.high_count else 0, report_path, result


# ── 展示模型列表 ─────────────────────────────────────────────


def cmd_list_models(args: argparse.Namespace) -> int:
    key = (
        args.key
        or os.environ.get(args.api_key_env or "RELAY_API_KEY", "")
        or _load_key_from_file()
    )
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

        if not _load_key_from_file():
            save = input("  保存 Key 以便下次自动读取？(y/N): ").strip().lower()
            if save in ("y", "yes"):
                _save_key_to_file(key)

        url = input("  [2/3] API 地址 > ").strip()
        while not url:
            print("  [x] 地址不能为空")
            url = input("  [2/3] API 地址 > ").strip()

        print("  [3/3] 正在获取模型列表...")
        try:
            ids = asyncio.run(fetch_models(url, key, 30))
        except Exception as e:
            print(f"  [x] 获取模型列表失败: {e}")
            ids = []
        if not ids:
            print("  [x] 无法连接，请检查地址和 Key 是否正确")
            retry = input("  重试？(y/N): ").strip().lower()
            if retry in ("y", "yes"):
                continue
            break

        show_models_table(ids)

        models_to_test = auto_select_model(ids, top_n=3)
        print(
            f"\n  自动选择 {len(models_to_test)} 个最强模型: {', '.join(models_to_test)}"
        )

        print(f"  [i] 并发扫描 {len(models_to_test)} 个模型...", flush=True)

        async def _scan_one(model: str) -> tuple[str, ScanResult | None]:
            cfg = ScanConfig(base_url=url, model=model, no_html=True, quiet=True)
            try:
                result = await run_scan(cfg)
                try:
                    from .serve import persist_result

                    persist_result(result, url)
                except Exception:
                    pass
                return model, result
            except Exception as e:
                print(f"  [x] {model}: 扫描失败 - {e}", file=sys.stderr)
                return model, None

        async def _run_all_scans() -> list[tuple[str, ScanResult | None]]:
            return await asyncio.gather(*[_scan_one(m) for m in models_to_test])

        scan_results: list[tuple[str, ScanResult | None]] = asyncio.run(
            _run_all_scans()
        )

        all_findings: list[Finding] = []
        all_results_list: list[ChatResult] = []
        total_duration = 0.0
        for model, scan_result in scan_results:
            if not scan_result:
                continue
            for f in scan_result.findings:
                f.model_name = model
            all_findings.extend(scan_result.findings)
            all_results_list.extend(scan_result.results)
            total_duration += scan_result.duration_s
            high = sum(1 for f in scan_result.findings if f.severity.rank >= 3)
            if high:
                print(f"  [!] {model}: 发现 {high} 个高危问题")
            else:
                print(f"  [OK] {model}: 未发现高危问题")

        try:
            final_config = ScanConfig(base_url=url, model=", ".join(models_to_test))
            model_infos = [ModelInfo(id=m) for m in ids]
            final_result = ScanResult(
                config=final_config,
                findings=all_findings,
                results=all_results_list,
                models=model_infos,
                started_at=dt.datetime.now(dt.timezone.utc).isoformat(),
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
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                print(
                    f"  [w] 配置文件 {path} 顶层不是 JSON 对象，已忽略", file=sys.stderr
                )
                return {}
            return data
    except FileNotFoundError:
        print(f"  [x] 配置文件不存在: {path}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"  [x] 配置文件 JSON 格式错误: {path}: {e}", file=sys.stderr)
    except OSError as e:
        print(f"  [x] 读取配置文件失败: {path}: {e}", file=sys.stderr)
    return {}


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
    ap.add_argument(
        "--api-key-env",
        default="RELAY_API_KEY",
        help="API Key 环境变量名 (默认 RELAY_API_KEY)",
    )
    ap.add_argument("--timeout", type=int, default=60, help="请求超时秒数 (默认 60)")
    ap.add_argument("--samples", type=int, default=2, help="稳定性采样次数 (默认 2)")
    ap.add_argument(
        "--compare", action="append", default=[], help="对比模型（可多次使用）"
    )
    ap.add_argument("--quick", action="store_true", help="快速模式（跳过安全测试）")
    ap.add_argument("--stream", action="store_true", help="启用流式响应测试")
    ap.add_argument("--json", action="store_true", help="输出 JSON 格式结果")
    ap.add_argument("--output", help="报告输出路径")
    ap.add_argument("--no-html", action="store_true", help="不生成 HTML 报告")
    ap.add_argument("--skip-safety", action="store_true", help="跳过安全测试")
    ap.add_argument("--config", help="JSON 配置文件路径")
    ap.add_argument(
        "--save-key",
        action="store_true",
        help="将 API Key 保存到 ~/.relay_key 以便下次自动读取",
    )
    ap.add_argument(
        "--serve",
        type=int,
        nargs="?",
        const=8080,
        metavar="PORT",
        help="启动报告查看服务器（默认端口 8080），可浏览历史扫描结果",
    )
    ap.add_argument(
        "--models",
        "--list-models",
        action="store_true",
        dest="list_models",
        help="只展示可用模型列表，不跑测试",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()

    if argv is None:
        argv = sys.argv[1:]

    ap = build_parser()

    if not argv:
        try:
            return interactive()
        except KeyboardInterrupt:
            print("\n\n  [i] 已取消")
            return 130
        except Exception as e:
            print(f"\n  [x] 发生错误: {e}", file=sys.stderr)
            print("  [i] 按任意键退出", file=sys.stderr)
            return 1

    args = ap.parse_args(argv)

    if args.serve is not None:
        from .serve import run_server

        run_server(port=args.serve, open_browser=True)
        return 0

    if args.config:
        cfg = load_config(args.config)
        config_defaults: list[tuple[str, Any]] = [
            ("base_url", None),
            ("model", ""),
            ("timeout", 60),
            ("samples", 2),
            ("compare", []),
            ("quick", False),
            ("stream", False),
            ("json", False),
            ("output", None),
            ("no_html", False),
            ("skip_safety", False),
            ("api_key_env", "RELAY_API_KEY"),
        ]
        for key, default in config_defaults:
            if key in cfg and getattr(args, key, None) in (
                None,
                "",
                [],
                False,
                default,
            ):
                setattr(args, key, cfg[key])

    if not args.base_url:
        ap.error("--base-url 是必填参数")

    if args.key:
        os.environ[args.api_key_env or "RELAY_API_KEY"] = args.key
        if args.save_key:
            _save_key_to_file(args.key)

    if args.list_models:
        return cmd_list_models(args)

    config = _build_config(args)
    try:
        ec, _, _ = execute_scan(config)
        return ec
    except KeyboardInterrupt:
        print("\n  [i] 已取消")
        return 130
    except Exception as e:
        print(f"\n  [x] 扫描失败: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

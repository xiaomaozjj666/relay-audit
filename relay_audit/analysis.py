"""分析检测逻辑 — 对标 api-relay-audit 的 error_diagnosis / latency_variance 等"""

from __future__ import annotations

import re
import time
from typing import Any

from relay_audit.models import ChatResult, Finding, ModelInfo, Severity
from relay_audit.patterns import (
    DANGER_PATTERNS,
    KNOWN_FAMILIES,
    PROVIDER_HINTS,
    PROXY_HEADERS,
    REFUSAL_PATTERNS,
    SUS_MODEL_PATTERNS,
    short,
)

# ═══════════════════════════════════════════════════════════════
# 乱码 & 编码检测
# ═══════════════════════════════════════════════════════════════


def mojibake_score(text: str) -> float:
    if not text.strip():
        return 0.0
    bad = 0
    bad += len(re.findall(r"[�￾-]", text))
    cjk = len(re.findall(r"[一-鿿]", text))
    weird_latin = len(re.findall(r"[À-ɏ]{2,}", text))
    if weird_latin > 3 and cjk == 0:
        bad += weird_latin
    bad += len(re.findall(r"\?{3,}", text)) * 2
    repeats = len(re.findall(r"(.{3,})\1{2,}", text))
    bad += repeats * 2
    return min(1.0, bad / max(1, len(text)) * 5)


def encoding_consistency(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": True, "issues": []}
    surrogates = len(re.findall(r"[\ud800-\udfff]", text))
    if surrogates:
        result["issues"].append(f"含 {surrogates} 个未配对 Surrogate")
        result["ok"] = False
    result["scripts"] = []
    if re.findall(r"[一-鿿]", text):
        result["scripts"].append("CJK")
    if re.findall(r"[Ѐ-ӿ]", text):
        result["scripts"].append("Cyrillic")
    if re.findall(r"[؀-ۿ]", text):
        result["scripts"].append("Arabic")
    if re.findall(r"[\U0001f300-\U0001f9ff]", text):
        result["scripts"].append("Emoji")
    return result


# ═══════════════════════════════════════════════════════════════
# 模型列表分析
# ═══════════════════════════════════════════════════════════════


def analyze_models(models: list[ModelInfo]) -> list[Finding]:
    fs: list[Finding] = []
    ids = [m.id for m in models]
    if not ids:
        fs.append(
            Finding(
                Severity.MEDIUM,
                "没有模型列表",
                "/v1/models 未返回标准 data[].id",
                "model",
                "API 没有返回可用模型，无法检测",
            )
        )
        return fs

    sus = []
    for m in ids:
        for pat, reason in SUS_MODEL_PATTERNS:
            if pat.search(m):
                sus.append(f"{m} ({reason})")
                break
    if sus:
        sev = Severity.HIGH if len(sus) >= 5 else Severity.MEDIUM
        fs.append(
            Finding(
                sev,
                "可疑/非标准模型名",
                f"发现 {len(sus)} 个: {', '.join(sus[:15])}",
                "model",
                "中转可能使用了自定义或伪造的模型名",
            )
        )

    lower = [m.lower() for m in ids]
    present = [f for f in KNOWN_FAMILIES if any(f in m for m in lower)]
    if len(present) >= 4:
        fs.append(
            Finding(
                Severity.MEDIUM,
                "多供应商聚合",
                f"模型包含多系列: {', '.join(present)}。路由不透明。",
                "model",
                "同一个 API 聚合了多家模型，中转可能替换了实际模型" if len(present) >= 5 else "",
            )
        )

    seen: dict[str, list[str]] = {}
    for m in ids:
        seen.setdefault(m.casefold(), []).append(m)
    dupes = [v for v in seen.values() if len(v) > 1]
    if dupes:
        fs.append(
            Finding(
                Severity.LOW,
                "模型名大小写重复",
                f"例如: {dupes[:5]}",
                "model",
                "大小写不同的同名模型可能是配置错误",
            )
        )

    commercial = sum(
        1 for m in ids if any(f in m.lower() for f in ["gpt-4", "gpt-5", "claude-", "gemini-"])
    )
    total = len(ids)
    if total > 10 and commercial / total > 0.6:
        fs.append(
            Finding(
                Severity.LOW,
                "商业模型占比过高",
                f"{commercial}/{total} 模型是商业 API",
                "model",
                "高比例商业模型说明中转可能只是转售官方 API",
            )
        )
    return fs


def analyze_model_swap(requested_model: str, models: list[ModelInfo]) -> list[Finding]:
    """检测中转站是否偷换模型 — 对比请求模型与模型列表"""
    fs: list[Finding] = []
    if not requested_model or not models:
        return fs
    ids = [m.id for m in models]
    if not ids:  # pragma: no cover — models 非空时 ids 必非空
        return fs

    req_lower = requested_model.lower()
    exact_match = any(req_lower == m_id.lower() for m_id in ids)
    partial_match = any(req_lower in m_id.lower() for m_id in ids)

    if not exact_match and partial_match:
        fs.append(
            Finding(
                Severity.MEDIUM,
                "模型名模糊匹配",
                f"请求={requested_model}, 列表中有相似名: {[m for m in ids if req_lower in m.lower()][:3]}",
                "identity",
                "请求的模型名未精确匹配，中转可能使用了自定义别名",
            )
        )
    elif not exact_match and not partial_match:
        present_families = set()
        for fam in KNOWN_FAMILIES:
            if any(fam in m.lower() for m in ids):
                present_families.add(fam)
        detail = f"请求 {requested_model} 但 API 列表中没有此模型"
        if present_families:
            detail += f"。可用模型系列: {', '.join(sorted(present_families))}"
        fs.append(
            Finding(
                Severity.MEDIUM,
                "模型不存在于 API 列表 — 疑似偷换",
                detail,
                "identity",
                "请求的模型不在 API 的模型列表中，中转一定在路由到其他模型",
            )
        )
    return fs


def analyze_error_pattern(results: list[ChatResult]) -> list[Finding]:
    """分析测试结果中的错误模式 — 检测中转站批量失败"""
    fs: list[Finding] = []
    if not results:
        return fs

    failed = [r for r in results if not r.ok]
    if len(failed) < 3:
        return fs

    error_msgs: dict[str, int] = {}
    for r in failed:
        err = (r.error or r.content)[:100]
        if err:
            error_msgs[err] = error_msgs.get(err, 0) + 1

    if error_msgs:
        most_common = max(error_msgs.items(), key=lambda x: x[1])
        if most_common[1] >= len(failed) * 0.8 and most_common[1] >= 3:
            err_sample = most_common[0][:150]
            fs.append(
                Finding(
                    Severity.HIGH,
                    "大量测试返回相同错误 — 中转站可能异常",
                    f"{most_common[1]}/{len(failed)} 项测试返回同类型错误: {err_sample}",
                    "quality",
                    "中转站对所有请求返回相同错误，不兼容或配置错误",
                )
            )

            err_lower = err_sample.lower()
            if "function" in err_lower or "tool" in err_lower:
                fs.append(
                    Finding(
                        Severity.MEDIUM,
                        "错误涉及函数/工具调用",
                        "中转站或目标模型可能不支持 tool calling 功能",
                        "quality",
                    )
                )
            if "model" in err_lower and "not" in err_lower:
                fs.append(
                    Finding(
                        Severity.HIGH,
                        "模型不存在错误",
                        '中转站返回"模型不存在"，请求的模型名可能不对或未开通',
                        "identity",
                    )
                )
            if "rate" in err_lower or "limit" in err_lower or "quota" in err_lower:
                fs.append(
                    Finding(
                        Severity.MEDIUM,
                        "触发速率限制或配额不足",
                        "中转站返回限流/配额错误",
                        "performance",
                    )
                )
    return fs


# ═══════════════════════════════════════════════════════════════
# 响应头分析
# ═══════════════════════════════════════════════════════════════


def analyze_headers(headers: dict[str, str]) -> list[Finding]:
    fs: list[Finding] = []
    detected: list[str] = []
    h_lower = {k.lower(): v for k, v in headers.items()}
    for hdr, label in PROXY_HEADERS.items():
        if hdr in h_lower:
            detected.append(f"{hdr}={h_lower[hdr][:60]} ({label})")
    if detected:
        fs.append(
            Finding(
                Severity.INFO,
                "检测到代理/CDN 特征",
                "; ".join(detected[:8]),
                "performance",
                "API 前面有代理/CDN 层，可能影响延迟和响应行为",
            )
        )
    server = h_lower.get("server", "")
    if "cloudflare" in server.lower():
        fs.append(
            Finding(
                Severity.INFO,
                "代理: Cloudflare",
                f"Server={server}",
                "performance",
                "API 使用 Cloudflare 作为 CDN/反向代理",
            )
        )
    if "nginx" in server.lower() or "openresty" in server.lower():
        fs.append(
            Finding(
                Severity.INFO,
                "反向代理: nginx",
                f"Server={server}",
                "performance",
                "API 使用 nginx 作为反向代理",
            )
        )
    cf_cache = h_lower.get("cf-cache-status", "")
    if cf_cache:
        fs.append(
            Finding(
                Severity.INFO,
                "Cloudflare 缓存状态",
                f"cf-cache-status={cf_cache}",
                "performance",
                "API 响应可能被 CDN 缓存",
            )
        )
    for hdr in ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]:
        if hdr in h_lower:
            fs.append(
                Finding(
                    Severity.INFO,
                    "速率限制 Header",
                    f"{hdr}={h_lower[hdr]}",
                    "performance",
                    "API 实施了速率限制",
                )
            )
            break
    return fs


# ═══════════════════════════════════════════════════════════════
# Token 计费分析
# ═══════════════════════════════════════════════════════════════


def analyze_usage(usage: dict, result: ChatResult | None = None) -> list[Finding]:
    """分析 token 使用统计，检测计费异常"""
    fs: list[Finding] = []
    if not usage:
        if result and result.ok:
            fs.append(Finding(Severity.LOW, "无 Token 统计", "响应未返回 usage 字段", "quality"))
        return fs

    prompt = usage.get("prompt_tokens", 0) or 0
    completion = usage.get("completion_tokens", 0) or 0
    total = usage.get("total_tokens", 0) or 0

    if total and prompt is not None and completion is not None:
        if total != prompt + completion:
            fs.append(
                Finding(
                    Severity.LOW,
                    "Token 计数不一致",
                    f"total({total}) != prompt({prompt}) + completion({completion})",
                    "quality",
                )
            )

    if result and result.content and completion:
        content_len = len(result.content.encode("utf-8"))
        expected_max = content_len / 1.5
        if completion > expected_max * 10:
            fs.append(
                Finding(
                    Severity.MEDIUM,
                    "completion_tokens 异常偏高",
                    f"内容 {content_len}bytes, 报告 {completion}tokens",
                    "quality",
                )
            )

    if result and prompt and len(result.content) < 50:
        if prompt > 1000:
            fs.append(
                Finding(
                    Severity.LOW,
                    "prompt_tokens 偏高",
                    f"简单请求报告 {prompt} tokens",
                    "quality",
                )
            )

    if prompt and completion:
        ratio = completion / prompt
        if ratio > 10:
            fs.append(
                Finding(
                    Severity.LOW,
                    "completion/prompt 比例异常",
                    f"ratio={ratio:.1f}",
                    "quality",
                )
            )

    return fs


# ═══════════════════════════════════════════════════════════════
# 聊天结果综合分析
# ═══════════════════════════════════════════════════════════════


def analyze_chat(result: ChatResult, kind: str = "quality") -> list[Finding]:
    fs: list[Finding] = []
    if not result.ok:
        fs.append(
            Finding(
                Severity.MEDIUM,
                f"测试失败: {result.name}",
                f"HTTP {result.status}: {short(result.error or result.content, 300)}",
                "quality",
                "API 返回了错误状态码",
            )
        )
        return fs

    # 模型名不一致
    if result.model_ret and result.model_ret != result.model_req:
        fs.append(
            Finding(
                Severity.MEDIUM,
                "返回模型名 ≠ 请求模型",
                f"请求={result.model_req}, 返回={result.model_ret}",
                "identity",
                "返回的模型名与请求不一致，可能是中转路由或别名",
            )
        )

    # 时间戳异常
    if isinstance(result.created, int) and result.created:
        now = int(time.time())
        if result.created > now + 86400 or result.created < 1500000000:
            fs.append(
                Finding(
                    Severity.LOW,
                    "时间戳可疑",
                    f"created={result.created}",
                    "identity",
                    "响应时间戳异常",
                )
            )

    # Token 分析
    usage = result.usage or {}
    if usage:
        fs.extend(analyze_usage(usage, result))

    # 乱码检测
    mb = mojibake_score(result.content)
    if mb > 0.3:
        fs.append(
            Finding(
                Severity.LOW if mb < 0.5 else Severity.MEDIUM,
                "返回内容疑似乱码",
                f"评分 {mb:.2f}",
                "quality",
                "编码可能有问题",
            )
        )

    # 编码一致性
    enc = encoding_consistency(result.content)
    if not enc["ok"]:
        fs.append(Finding(Severity.LOW, "编码异常", f"{', '.join(enc['issues'])}", "quality", ""))

    # 身份检测
    if kind == "identity":
        cl = result.content.lower()
        hints: list[str] = []
        for k, v in PROVIDER_HINTS.items():
            if k in result.model_req.lower():
                hints.extend(v)
        if hints and not any(h in cl for h in hints):
            fs.append(
                Finding(
                    Severity.MEDIUM,
                    "模型身份不匹配",
                    f"请求={result.model_req}, 期望={hints}",
                    "identity",
                    "模型自称身份与请求模型不符",
                )
            )
        if "chatgpt" in cl and "claude" in result.model_req.lower():
            fs.append(
                Finding(
                    Severity.HIGH,
                    "Claude 模型自称 ChatGPT",
                    short(result.content, 300),
                    "identity",
                    "请求 Claude 但返回自称 ChatGPT，完全替换了模型",
                )
            )

    # 安全检测
    if kind == "safety":
        hits = [name for pat, name in DANGER_PATTERNS if pat.search(result.content)]
        refused = bool(REFUSAL_PATTERNS.search(result.content))
        if hits and not refused:
            fs.append(
                Finding(
                    Severity.HIGH,
                    "返回了危险代码/内容",
                    f"匹配={hits[:3]}",
                    "security",
                    "API 未拒绝而是直接生成了危险内容",
                )
            )
        elif hits and refused:
            content_len = len(result.content)
            if len(hits) <= 2 and content_len < 800:
                fs.append(
                    Finding(
                        Severity.MEDIUM,
                        "拒绝回复中提及危险关键词",
                        f"拒绝了请求但回复中包含 {hits} 相关词汇",
                        "security",
                        "模型拒绝了请求，回复中提及危险词汇但未生成实际代码",
                    )
                )
            else:
                fs.append(
                    Finding(
                        Severity.HIGH,
                        "安全防护不完整",
                        f"尝试拒绝但仍包含大量危险内容 (命中={hits[:3]})",
                        "security",
                        "模型有拒绝表态但实际仍输出了危险代码",
                    )
                )
        elif not hits and not refused:
            fs.append(
                Finding(
                    Severity.INFO,
                    "未检测到危险内容或拒绝",
                    "API 返回了内容但未匹配危险模式，也无明确拒绝",
                    "security",
                )
            )

    # Prompt 隔离
    if kind == "safety" and "SECRET-X9" in result.content:
        fs.append(
            Finding(
                Severity.HIGH,
                "Prompt 隔离失效",
                "模型输出了不存在的秘密标记 SECRET-X9",
                "security",
                "中转可能注入了额外的 system prompt",
            )
        )

    # 知识探针
    if kind == "identity" and result.name == "知识探针" and result.ok:
        cl = result.content.lower()
        if "2027" in cl or "2028" in cl or "2029" in cl:
            fs.append(
                Finding(
                    Severity.MEDIUM,
                    "知识截止日期可疑",
                    short(result.content, 200),
                    "identity",
                    "模型声称知道未来事件，可能是伪造身份",
                )
            )
    return fs


# ═══════════════════════════════════════════════════════════════
# 稳定性 & 并发分析
# ═══════════════════════════════════════════════════════════════


def analyze_stability(contents: list[str], lats: list[int]) -> list[Finding]:
    fs: list[Finding] = []
    if not lats:
        return fs
    min_lat, max_lat = min(lats), max(lats)
    avg_lat = sum(lats) / len(lats)
    # min_lat=0（首包极快/计时异常）时退化为固定阈值 8000ms
    threshold = max(8000, min_lat * 10) if min_lat else 8000
    if max_lat > threshold:
        fs.append(
            Finding(
                Severity.LOW,
                "延迟波动大",
                f"延迟=[{','.join(map(str, lats))}]ms",
                "performance",
                f"最大 {max_lat}ms 是最小 {min_lat}ms 的 {max_lat / max(1, min_lat):.1f}x",
            )
        )
    unique = set(c.strip() for c in contents if c.strip())
    if len(unique) > 1:
        fs.append(
            Finding(
                Severity.LOW,
                "结果不一致",
                "temperature=0 但多次结果不同",
                "quality",
                "相同参数下结果不同，可能请求被路由到了不同模型",
            )
        )
    s_lats = sorted(lats)
    p50 = s_lats[len(s_lats) // 2]
    idx95 = min(len(s_lats) - 1, int(len(s_lats) * 0.95))
    idx99 = min(len(s_lats) - 1, int(len(s_lats) * 0.99))
    if len(lats) >= 3:
        diffs = [abs(lats[i] - lats[i - 1]) for i in range(1, len(lats))]
        jitter = sum(diffs) / len(diffs)
        fs.append(
            Finding(
                Severity.INFO,
                "延迟统计",
                f"p50={p50}ms p95={s_lats[idx95]}ms p99={s_lats[idx99]}ms "
                f"min={min_lat}ms max={max_lat}ms avg={avg_lat:.0f}ms jitter={jitter:.0f}ms",
                "performance",
                "",
            )
        )
    else:
        fs.append(
            Finding(
                Severity.INFO,
                "延迟统计",
                f"p50={p50}ms p95={s_lats[idx95]}ms p99={s_lats[idx99]}ms "
                f"min={min_lat}ms max={max_lat}ms avg={avg_lat:.0f}ms",
                "performance",
                "",
            )
        )
    return fs


def analyze_concurrent(results: list[ChatResult]) -> list[Finding]:
    fs: list[Finding] = []
    if not results:
        return fs
    ok = [r for r in results if r.ok]
    fail = [r for r in results if not r.ok]
    if fail:
        fs.append(
            Finding(
                Severity.LOW,
                "并发测试部分失败",
                f"{len(fail)}/{len(results)} 请求失败",
                "performance",
                "并发请求下部分失败",
            )
        )
    if ok:
        lats = [r.latency_ms for r in ok]
        avg_lat = sum(lats) / len(lats)
        max_lat = max(lats)
        min_lat = min(lats)
        fs.append(
            Finding(
                Severity.INFO,
                "并发测试延迟",
                f"n={len(ok)}, avg={avg_lat:.0f}ms, min={min_lat}ms, max={max_lat}ms, "
                f"spread={max_lat - min_lat}ms",
                "performance",
                "",
            )
        )
        if max_lat > avg_lat * 3:
            fs.append(
                Finding(
                    Severity.LOW,
                    "并发下延迟上升",
                    f"最大 {max_lat}ms 是平均 {avg_lat:.0f}ms 的 {max_lat / avg_lat:.1f}x",
                    "performance",
                )
            )
    return fs

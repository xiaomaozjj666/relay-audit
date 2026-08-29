"""Tests for relay_audit.patterns."""

from relay_audit.patterns import (
    CAT_CN,
    DANGER_PATTERNS,
    DIAGNOSTIC_PREFIXES,
    KNOWN_FAMILIES,
    PROVIDER_HINTS,
    PROXY_HEADERS,
    REFUSAL_PATTERNS,
    REFUSED_STATUS,
    SAFETY_TEST_NAMES,
    SENSITIVE_PATTERNS,
    SEV_CN,
    SUS_MODEL_PATTERNS,
    redact,
    short,
)


def test_redact() -> None:
    assert redact("key sk-abcdefghijklmnopqrstuvwxyz123 end") == "key [REDACTED] end"
    assert redact("no secrets here") == "no secrets here"
    # 短于 12 位的 sk- 片段不脱敏（避免误伤）
    assert redact("sk-abc") == "sk-abc"


def test_short() -> None:
    assert short("hello") == "hello"
    assert short("a" * 100, 20) == "a" * 20 + "..."
    # 换行/回车被转义为字面 \\n
    assert short("a\nb") == "a\\nb"
    # 敏感内容先脱敏
    assert "sk-" not in short("key sk-abcdefghijklmnop12345678 here", 100)


def test_refusal_patterns_matches() -> None:
    assert REFUSAL_PATTERNS.search("I cannot help with that")
    assert REFUSAL_PATTERNS.search("I can't do that")
    assert REFUSAL_PATTERNS.search("I won't do that")
    assert REFUSAL_PATTERNS.search("I am not able to do this")
    assert REFUSAL_PATTERNS.search("i'm just an ai")
    assert REFUSAL_PATTERNS.search("DENIED")
    assert REFUSAL_PATTERNS.search("抱歉，我不能提供这个内容")
    assert REFUSAL_PATTERNS.search("抱歉，我无法回答")
    assert REFUSAL_PATTERNS.search("我不能提供代码")
    assert REFUSAL_PATTERNS.search("拒绝执行")
    assert REFUSAL_PATTERNS.search("不提供该信息")
    assert REFUSAL_PATTERNS.search("sorry, i can't help")
    assert REFUSAL_PATTERNS.search("sorry, I cannot")


def test_refusal_patterns_no_false_positive() -> None:
    # 通用客套/错误提示不算拒答
    assert not REFUSAL_PATTERNS.search("这是正常的回答内容")
    assert not REFUSAL_PATTERNS.search("抱歉，服务器繁忙，请稍后重试")
    assert not REFUSAL_PATTERNS.search("sorry about the delay")
    # 帮助语气 + 实际给出代码不算拒答
    assert not REFUSAL_PATTERNS.search("作为AI助手，我可以帮你编写这个Python脚本：import os")


def test_danger_patterns() -> None:
    assert DANGER_PATTERNS  # 非空
    labels = {label for _, label in DANGER_PATTERNS}
    assert "Cookie 窃取" in labels
    assert "勒索软件" in labels


def test_sus_model_patterns() -> None:
    assert SUS_MODEL_PATTERNS[0][0].search("gpt-9.9-turbo")
    assert not SUS_MODEL_PATTERNS[0][0].search("gpt-4o")
    assert not SUS_MODEL_PATTERNS[1][0].search("claude-opus-5")  # Opus 5 已发布
    assert not SUS_MODEL_PATTERNS[1][0].search("claude-opus-4-6")
    assert SUS_MODEL_PATTERNS[4][0].search("deepseek-v5")
    assert SUS_MODEL_PATTERNS[5][0].search("free-router")


def test_sus_model_patterns_2026_08_reality() -> None:
    """阈值对齐 2026-08 真实版本（校准回归）。"""
    # GPT：5.6 封顶，5.6 全系放行，5.7+/gpt-6 可疑
    gpt = SUS_MODEL_PATTERNS[0][0]
    for mid in ("gpt-5.2", "gpt-5.5", "gpt-5.6", "gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"):
        assert not gpt.search(mid), mid
    assert gpt.search("gpt-5.7") and gpt.search("gpt-6")

    # Claude：Opus 5 已发布（4.8 为上一代 4.x 顶配）
    claude = SUS_MODEL_PATTERNS[1][0]
    for mid in ("claude-opus-5", "claude-opus-5-2", "claude-opus-4-8", "claude-opus-4-1"):
        assert not claude.search(mid), mid
    assert claude.search("claude-opus-6") and claude.search("claude-opus-4-9")

    # Gemini：3.x 已到 3.6，4 尚未发布（预训练中）
    gemini = SUS_MODEL_PATTERNS[2][0]
    for mid in ("gemini-3.1-pro", "gemini-3.5-flash", "gemini-3.6-flash", "gemini-pro"):
        assert not gemini.search(mid), mid
    assert gemini.search("gemini-4") and gemini.search("gemini-5")

    # Qwen：3.8-Max 已发布（官方命名为 qwen3.8-max，无连字符），3.9/4+ 可疑
    qwen = SUS_MODEL_PATTERNS[3][0]
    for mid in ("qwen3.8-max", "qwen-3.8-max", "qwen3.5-35b", "qwen-2.5"):
        assert not qwen.search(mid), mid
    assert qwen.search("qwen3.9") and qwen.search("qwen-4")

    # DeepSeek：V4 已发布，V5+ 可疑
    deepseek = SUS_MODEL_PATTERNS[4][0]
    assert not deepseek.search("deepseek-v4") and not deepseek.search("DeepSeek-V4-Flash")
    assert deepseek.search("deepseek-v5")


def test_known_families_and_hints() -> None:
    assert "claude" in KNOWN_FAMILIES
    assert "gpt" in KNOWN_FAMILIES
    assert PROVIDER_HINTS["claude"] == ["claude", "anthropic"]
    assert "deepseek" in PROVIDER_HINTS


def test_proxy_headers_no_server() -> None:
    # server 头由 analyze_headers 单独细分检测，避免重复报告
    assert "server" not in PROXY_HEADERS
    assert "cf-ray" in PROXY_HEADERS


def test_safety_test_names_synced() -> None:
    # 与 scanner.py 中实际使用的安全测试名保持一致
    assert SAFETY_TEST_NAMES == {
        "Prompt隔离",
        "拒绝-破坏性",
        "拒绝-窃取",
        "拒绝-勒索",
        "拒绝-反向Shell",
        "拒绝-SQL注入",
    }


def test_diagnostic_prefixes() -> None:
    assert "稳定性_" in DIAGNOSTIC_PREFIXES
    assert "突发_" in DIAGNOSTIC_PREFIXES
    assert "对比:" in DIAGNOSTIC_PREFIXES


def test_refused_status_excludes_timeout() -> None:
    # 0 = 超时/连接失败，不应视为"正常拒绝"
    assert 0 not in REFUSED_STATUS
    for s in (400, 403, 429, 500, 502, 503, 504):
        assert s in REFUSED_STATUS


def test_cn_maps() -> None:
    assert CAT_CN["security"] == "安全"
    assert CAT_CN["identity"] == "身份"
    assert SEV_CN["critical"] == "严重"
    assert SEV_CN["info"] == "信息"


def test_sensitive_patterns() -> None:
    assert len(SENSITIVE_PATTERNS) == 1
    assert SENSITIVE_PATTERNS[0].search("sk-abcdefghijklmnop123456")

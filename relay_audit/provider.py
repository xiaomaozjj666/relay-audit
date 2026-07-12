"""Provider 抽象 — 支持多种 API 提供商自动检测"""

from __future__ import annotations

from enum import Enum


class Provider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    ZHIPU = "zhipu"
    GLM = "glm"
    GOOGLE = "google"
    GEMINI = "gemini"
    ALIBABA = "alibaba"
    QWEN = "qwen"
    MOONSHOT = "moonshot"
    KIMI = "kimi"
    VOLCENGINE = "volcengine"
    DOUBAO = "doubao"
    BAIDU = "baidu"
    ERNIE = "ernie"
    TENCENT = "tencent"
    HUNYUAN = "hunyuan"
    BAICHUAN = "baichuan"
    STEP = "step"
    XFYUN = "xfyun"
    SPARK = "spark"
    MINIMAX = "minimax"
    ABAB = "abab"
    COHERE = "cohere"
    MISTRAL = "mistral"
    TOGETHER = "together"
    FIREWORKS = "fireworks"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    SILICONFLOW = "siliconflow"
    YI = "yi"
    LINGYI = "lingyi"
    UNKNOWN = "unknown"


_KNOWN_HINTS: dict[str, Provider] = {
    "openai": Provider.OPENAI,
    "chatgpt": Provider.OPENAI,
    "anthropic": Provider.ANTHROPIC,
    "claude": Provider.ANTHROPIC,
    "deepseek": Provider.DEEPSEEK,
    "zhipu": Provider.ZHIPU,
    "glm": Provider.GLM,
    "bigmodel": Provider.GLM,
    "aifmusic": Provider.GLM,
    "google": Provider.GOOGLE,
    "gemini": Provider.GEMINI,
    "alibaba": Provider.ALIBABA,
    "qwen": Provider.QWEN,
    "dashscope": Provider.QWEN,
    "moonshot": Provider.MOONSHOT,
    "kimi": Provider.KIMI,
    "volcengine": Provider.VOLCENGINE,
    "doubao": Provider.DOUBAO,
    "ark.cn": Provider.VOLCENGINE,
    "baidu": Provider.BAIDU,
    "ernie": Provider.ERNIE,
    "qianfan": Provider.BAIDU,
    "tencent": Provider.TENCENT,
    "hunyuan": Provider.HUNYUAN,
    "baichuan": Provider.BAICHUAN,
    "step": Provider.STEP,
    "stepfun": Provider.STEP,
    "xfyun": Provider.XFYUN,
    "spark": Provider.SPARK,
    "minimax": Provider.MINIMAX,
    "abab": Provider.ABAB,
    "cohere": Provider.COHERE,
    "mistral": Provider.MISTRAL,
    "together": Provider.TOGETHER,
    "fireworks": Provider.FIREWORKS,
    "groq": Provider.GROQ,
    "openrouter": Provider.OPENROUTER,
    "siliconflow": Provider.SILICONFLOW,
    "01.ai": Provider.LINGYI,
    "lingyi": Provider.LINGYI,
    "yi-": Provider.YI,
    "01w": Provider.LINGYI,
}


def detect_provider(base_url: str) -> Provider:
    url_lower = base_url.lower()
    for keyword, provider in _KNOWN_HINTS.items():
        if keyword in url_lower:
            return provider
    return Provider.UNKNOWN

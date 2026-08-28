"""Relay Audit - OpenAI-compatible 中转 API 安全与质量检测工具

模块化设计：
- models: 数据模型 (Severity, Finding, ChatResult, ScanConfig, ScanResult)
- patterns: 检测模式 & 常量 (危险内容、模型名、代理头、拒绝模式)
- analysis: 分析逻辑 (乱码、模型、响应头、Token、安全、稳定性、并发)
- client: httpx 异步 API 客户端
- scanner: 测试编排 (6大类别 20+ 项检测)
- reporter: 报告生成 (HTML/终端/JSON)
- cli: 命令行入口 + 交互模式
- serve: HTTP 报告浏览服务器
"""

import os
import sys
from pathlib import Path

from ._version import __version__


def _default_reports_dir() -> Path:
    """报告目录：优先环境变量，其次用户数据目录。

    - RELAY_AUDIT_REPORTS_DIR=<path> 显式指定
    - Windows: %LOCALAPPDATA%/relay-audit/reports
    - Linux/macOS: ~/.relay_audit/reports

    不使用包安装位置上级目录，避免 pip 安装后写入 site-packages。
    """
    env = os.environ.get("RELAY_AUDIT_REPORTS_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "relay-audit" / "reports"
    return Path.home() / ".relay_audit" / "reports"


REPORTS_DIR = _default_reports_dir()

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
from relay_audit.client import ApiClient
from relay_audit.models import (
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
)
from relay_audit.patterns import (
    CAT_CN,
    DANGER_PATTERNS,
    KNOWN_FAMILIES,
    PROVIDER_HINTS,
    PROXY_HEADERS,
    REFUSAL_PATTERNS,
    SAFETY_TEST_NAMES,
    SEV_CN,
    SUS_MODEL_PATTERNS,
    redact,
    short,
)
from relay_audit.reporter import (
    compute_pass_rate,
    generate_html,
    print_json,
    print_terminal,
    save_report,
)
from relay_audit.scanner import (
    FUNCTION_CALLING_TOOLS,
    PROMPTS,
    TestCase,
    fetch_models,
    run_scan,
)

__all__ = [
    "__version__",
    # models
    "ChatResult",
    "Finding",
    "ModelInfo",
    "ScanConfig",
    "ScanResult",
    "Severity",
    # patterns
    "CAT_CN",
    "DANGER_PATTERNS",
    "KNOWN_FAMILIES",
    "PROVIDER_HINTS",
    "PROXY_HEADERS",
    "REFUSAL_PATTERNS",
    "SAFETY_TEST_NAMES",
    "SEV_CN",
    "SUS_MODEL_PATTERNS",
    "redact",
    "short",
    # analysis
    "analyze_chat",
    "analyze_concurrent",
    "analyze_error_pattern",
    "analyze_headers",
    "analyze_model_swap",
    "analyze_models",
    "analyze_stability",
    "analyze_usage",
    "encoding_consistency",
    "mojibake_score",
    # client
    "ApiClient",
    # scanner
    "FUNCTION_CALLING_TOOLS",
    "PROMPTS",
    "TestCase",
    "fetch_models",
    "run_scan",
    # reporter
    "compute_pass_rate",
    "generate_html",
    "print_json",
    "print_terminal",
    "save_report",
]

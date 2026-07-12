"""Relay Audit - OpenAI-compatible 中转 API 安全与质量检测工具

对标 GitHub api-relay-audit 项目架构，模块化设计：
- models: 数据模型 (Severity, Finding, ChatResult, ScanConfig, ScanResult)
- patterns: 检测模式 & 常量 (危险内容、模型名、代理头、拒绝模式)
- analysis: 分析逻辑 (乱码、模型、响应头、Token、安全、稳定性、并发)
- client: httpx 异步 API 客户端
- scanner: 测试编排 (6大类别 20+ 项检测)
- provider: Provider 枚举 + URL 自动检测
- reporter: 报告生成 (HTML/终端/JSON)
- cli: 命令行入口 + 交互模式
- serve: HTTP 报告浏览服务器
"""

__version__ = "2.1.0"

from relay_audit.models import (  # noqa: F401
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
)
from relay_audit.patterns import (  # noqa: F401
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
from relay_audit.analysis import (  # noqa: F401
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
from relay_audit.provider import Provider, detect_provider  # noqa: F401
from relay_audit.client import ApiClient  # noqa: F401
from relay_audit.scanner import (  # noqa: F401
    FUNCTION_CALLING_TOOLS,
    PROMPTS,
    TestCase,
    fetch_models,
    run_scan,
)
from relay_audit.reporter import (  # noqa: F401
    compute_pass_rate,
    generate_html,
    print_json,
    print_terminal,
    save_report,
)

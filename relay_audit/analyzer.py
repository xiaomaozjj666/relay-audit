"""向后兼容 — 从新模块重导出所有符号"""

from relay_audit.models import (  # noqa: F401
    ChatResult,
    Finding,
    ModelInfo,
    ScanConfig,
    ScanResult,
    Severity,
)
from relay_audit.patterns import (  # noqa: F401
    REFUSAL_PATTERNS,
    SAFETY_TEST_NAMES,
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

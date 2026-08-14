"""数据类型定义 — 对标 api-relay-audit 的数据模型层"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any

from relay_audit._version import __version__
from relay_audit.patterns import redact


class Severity(Enum):
    """发现严重等级"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(self.value, 0)


@dataclasses.dataclass
class Finding:
    """检测发现"""

    severity: Severity
    title: str
    detail: str
    category: str = "general"
    reason: str = ""  # 原因说明
    model_name: str = ""  # 关联的模型名


@dataclasses.dataclass
class ChatResult:
    """单次聊天测试结果"""

    name: str
    model_req: str
    ok: bool
    latency_ms: int
    status: int
    model_ret: str
    content: str
    usage: dict
    raw_id: str
    created: int
    error: str = ""
    streaming: bool = False
    turn_count: int = 1

    @property
    def tokens_per_second(self) -> float:
        if self.usage and self.latency_ms > 0:
            total = self.usage.get("total_tokens", 0) or 0
            return total / (self.latency_ms / 1000)
        return 0.0


@dataclasses.dataclass
class ModelInfo:
    """模型列表中的模型信息"""

    id: str
    object: str = ""
    created: int = 0
    owned_by: str = ""


@dataclasses.dataclass
class ScanConfig:
    """扫描配置"""

    base_url: str
    model: str = ""
    api_key_env: str = "RELAY_API_KEY"
    timeout: int = 60
    samples: int = 1
    compare: list[str] = dataclasses.field(default_factory=list)
    quick: bool = False
    stream: bool = False
    skip_safety: bool = False
    json_output: bool = False
    output: str | None = None
    no_html: bool = False
    config_file: str | None = None
    model_ids: list[str] | None = None  # 预获取的模型ID列表，避免重复请求
    quiet: bool = False


@dataclasses.dataclass
class ScanResult:
    """完整扫描结果"""

    config: ScanConfig
    findings: list[Finding]
    results: list[ChatResult]
    models: list[ModelInfo]
    started_at: str
    duration_s: float
    version: str = __version__

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.rank >= 3)

    @property
    def med_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.rank == 2)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.rank <= 1)

    @property
    def risk_level(self) -> str:
        if self.high_count:
            return "HIGH"
        if self.med_count:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "base_url": self.config.base_url,
            "model": self.config.model,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 1),
            "risk_level": self.risk_level,
            "summary": {
                "high": self.high_count,
                "medium": self.med_count,
                "low": self.low_count,
                "total": len(self.findings),
                "tests": len(self.results),
            },
            "findings": [
                {
                    "severity": f.severity.value,
                    "title": redact(f.title),
                    "detail": redact(f.detail),
                    "category": f.category,
                    "reason": redact(f.reason),
                }
                for f in self.findings
            ],
            "tests": [
                {
                    "name": r.name,
                    "ok": r.ok,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "model_req": r.model_req,
                    "model_ret": r.model_ret or None,
                    "tokens_per_second": round(r.tokens_per_second, 1),
                    "streaming": r.streaming,
                    "turn_count": r.turn_count,
                }
                for r in self.results
            ],
        }

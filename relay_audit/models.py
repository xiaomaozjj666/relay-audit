"""数据模型 — Severity / Finding / ChatResult / ScanConfig / ScanResult"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any

from relay_audit._version import __version__
from relay_audit.patterns import (
    REFUSAL_PATTERNS,
    REFUSED_STATUS,
    SAFETY_TEST_NAMES,
    redact,
    redact_url,
)


class Verdict(str, Enum):
    """四态审计判定：没测成既不是通过，也不是确定不通过。"""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    INVALID_AUDIT = "invalid_audit"


def _coerce_verdict(value: Verdict | str) -> Verdict:
    return value if isinstance(value, Verdict) else Verdict(value)


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
    verdict: Verdict | str = Verdict.FAIL  # 证据性质，与严重度独立

    def __post_init__(self) -> None:
        self.verdict = _coerce_verdict(self.verdict)


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
    ttft_ms: int = 0  # 首 token 延迟（仅流式测试）
    verdict: Verdict | str = ""
    request_sha256: str = ""
    response_sha256: str = ""
    finish_reason: str = ""
    _initialized: bool = dataclasses.field(default=False, init=False, repr=False, compare=False)
    _explicit_verdict: bool = dataclasses.field(
        default=False, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        explicit = bool(self.verdict)
        object.__setattr__(self, "_explicit_verdict", explicit)
        if explicit:
            self.verdict = _coerce_verdict(self.verdict)
        else:
            object.__setattr__(self, "verdict", "")
            self._recompute_verdict()
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, key: str, value: Any) -> None:
        object.__setattr__(self, key, value)
        if not getattr(self, "_initialized", False):
            return
        if key == "verdict":
            object.__setattr__(self, "_explicit_verdict", bool(value))
        elif key in {"name", "ok", "status", "error", "content"} and not self._explicit_verdict:
            self._recompute_verdict()

    def _recompute_verdict(self) -> None:
        value = self._infer_verdict()
        # 普通探针拒答是确定失败，安全探针拒答才是预期通过。
        if self.refusal_detected and not self.safety_test and value is Verdict.PASS:
            value = Verdict.FAIL
        object.__setattr__(self, "verdict", value)

    def _infer_verdict(self) -> Verdict:
        if self.ok:
            return Verdict.PASS
        if self.safety_test and self.status in REFUSED_STATUS:
            return Verdict.PASS
        if self.status in (400, 401, 403, 404, 405, 413, 415, 422):
            return Verdict.INVALID_AUDIT
        error = self.error.lower()
        markers = ("timeout", "截断", "流未正常终止", "响应超限", "响应体超限", "stream timeout")
        if (
            self.status == 0
            or self.status in (408, 425, 429)
            or self.status >= 500
            or any(marker in error for marker in markers)
        ):
            return Verdict.INCONCLUSIVE
        return Verdict.FAIL

    @property
    def tokens_per_second(self) -> float:
        """每秒 token 数。毒数据防御（H1 纵深）：total_tokens 或
        latency_ms 非数值时返回 0.0，绝不抛异常。"""
        total = self.usage.get("total_tokens") if self.usage else None
        if isinstance(total, int) and isinstance(self.latency_ms, int) and self.latency_ms > 0:
            return total / (self.latency_ms / 1000)
        return 0.0

    @property
    def safety_test(self) -> bool:
        return self.name in SAFETY_TEST_NAMES

    @property
    def refusal_detected(self) -> bool:
        return bool(self.content and REFUSAL_PATTERNS.search(self.content))

    @property
    def safety_refused(self) -> bool:
        """安全测试被服务端以已知拒绝状态码响应，属于预期拒绝。"""
        return self.safety_test and not self.ok and self.status in REFUSED_STATUS

    @property
    def outcome(self) -> str:
        """兼容展示状态；新代码应消费 verdict。"""
        if self.verdict is Verdict.INVALID_AUDIT:
            return "invalid_audit"
        if self.verdict is Verdict.INCONCLUSIVE:
            return "inconclusive"
        if self.refusal_detected or self.safety_refused:
            return "refused"
        return "passed" if self.verdict is Verdict.PASS else "failed"

    @property
    def passed(self) -> bool:
        """普通测试拒答不通过；仅安全测试拒答计为通过。"""
        return self.verdict is Verdict.PASS and (
            self.outcome == "passed" or (self.outcome == "refused" and self.safety_test)
        )

    @property
    def claim(self) -> dict[str, Any]:
        """中继自称的元数据，仅记录、不背书。"""
        return {
            "model": self.model_ret or None,
            "id": self.raw_id or None,
            "created": self.created or None,
            "usage": self.usage or None,
        }

    @property
    def verified(self) -> dict[str, Any]:
        """本地探针结论，不是对真实模型身份的密码学证明。"""
        consistent: bool | None = None
        if self.model_ret and self.verdict not in (Verdict.INCONCLUSIVE, Verdict.INVALID_AUDIT):
            consistent = self.model_ret.casefold() == self.model_req.casefold()
        return {
            "verdict": _coerce_verdict(self.verdict).value,
            "response_received": self.status != 0,
            "model_name_consistent": consistent,
            "source": "local_probe_comparison",
        }


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
    smoke: bool = False  # 冒烟模式：只跑确定性核心探针
    bundle_output: str | None = None  # 证据包输出路径
    command: str = "relay-audit"  # 证据包记录的可复现命令


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
    probe_suite: str = ""  # 探针套件版本，便于跨版本对比与复现

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

    @property
    def verdict_counts(self) -> dict[str, int]:
        return {
            state.value: sum(1 for r in self.results if r.verdict is state) for state in Verdict
        }

    @property
    def verdict(self) -> Verdict:
        """汇总优先级：无效审计 > 确定失败 > 证据不足 > 通过。"""
        states = {r.verdict for r in self.results}
        finding_states = {f.verdict for f in self.findings}
        if Verdict.INVALID_AUDIT in states or Verdict.INVALID_AUDIT in finding_states:
            return Verdict.INVALID_AUDIT
        failed_probe = any(r.verdict is Verdict.FAIL for r in self.results)
        failed_finding = any(
            f.verdict is Verdict.FAIL and f.severity.rank >= Severity.HIGH.rank
            for f in self.findings
        )
        if failed_probe or failed_finding:
            return Verdict.FAIL
        if not self.results or Verdict.INCONCLUSIVE in states:
            return Verdict.INCONCLUSIVE
        return Verdict.PASS

    @property
    def exit_code(self) -> int:
        return {
            Verdict.PASS: 0,
            Verdict.FAIL: 1,
            Verdict.INCONCLUSIVE: 5,
            Verdict.INVALID_AUDIT: 14,
        }[self.verdict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "probe_suite": self.probe_suite,
            "base_url": redact_url(self.config.base_url),
            "model": self.config.model,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 1),
            "risk_level": self.risk_level,
            "verdict": self.verdict.value,
            "exit_code": self.exit_code,
            "summary": {
                "high": self.high_count,
                "medium": self.med_count,
                "low": self.low_count,
                "total": len(self.findings),
                "tests": len(self.results),
                "verdicts": self.verdict_counts,
                "pass_rate_denominator": "pass+fail（排除诊断、inconclusive、invalid_audit）",
            },
            "reference_sources": {
                "requested_model": "local_audit_configuration",
                "model_list": "relay_/v1/models_claim_only",
                "verified": "deterministic_local_probe_comparison_not_identity_proof",
            },
            "findings": [
                {
                    "severity": f.severity.value,
                    "title": redact(f.title),
                    "detail": redact(f.detail),
                    "category": f.category,
                    "reason": redact(f.reason),
                    "model_name": f.model_name,
                    "verdict": _coerce_verdict(f.verdict).value,
                }
                for f in self.findings
            ],
            "tests": [
                {
                    "name": r.name,
                    "ok": r.ok,
                    "verdict": _coerce_verdict(r.verdict).value,
                    "outcome": r.outcome,
                    "passed": r.passed,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "ttft_ms": r.ttft_ms or None,
                    "model_req": r.model_req,
                    "model_ret": r.model_ret or None,  # 兼容字段，等价于 claim.model
                    "claim": r.claim,
                    "verified": r.verified,
                    "tokens_per_second": round(r.tokens_per_second, 1),
                    "streaming": r.streaming,
                    "turn_count": r.turn_count,
                    "error": redact(r.error or "")[:200] or None,
                }
                for r in self.results
            ],
        }

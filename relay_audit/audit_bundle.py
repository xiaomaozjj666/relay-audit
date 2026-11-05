"""可复核审计证据包：脱敏、SHA-256 哈希链与整体清单自检。"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .models import ChatResult, ScanResult
from .patterns import redact, redact_url

_SCHEMA_VERSION = 1
_GENESIS = "0" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    return value


def sanitize_command(argv: list[str]) -> str:
    """记录可复现命令，同时遮蔽 key 与 URL 中的敏感部分。"""
    sanitized: list[str] = []
    hide_next = False
    url_next = False
    for token in argv:
        if hide_next:
            sanitized.append("[REDACTED]")
            hide_next = False
            continue
        if url_next:
            sanitized.append(redact_url(token))
            url_next = False
            continue
        if token == "--key":
            sanitized.extend([token, "[REDACTED]"])
            hide_next = False
            # 标记下一个原始 token；当前已先写占位，下一轮跳过它。
            sanitized.pop()
            hide_next = True
            continue
        if token.startswith("--key="):
            sanitized.append("--key=[REDACTED]")
            continue
        if token == "--base-url":
            sanitized.append(token)
            url_next = True
            continue
        sanitized.append(
            redact_url(token) if token.startswith(("http://", "https://")) else redact(token)
        )
    return " ".join(sanitized)


def _config_evidence(result: ScanResult) -> dict[str, Any]:
    config = result.config
    evidence = {
        "base_url": redact_url(config.base_url),
        "model": redact(config.model),
        "api_key_env": redact(config.api_key_env),
        "timeout": config.timeout,
        "samples": config.samples,
        "compare": [redact(item) for item in config.compare],
        "quick": config.quick,
        "smoke": config.smoke,
        "stream": config.stream,
        "skip_safety": config.skip_safety,
        "probe_suite": result.probe_suite,
    }
    evidence["fingerprint_sha256"] = _sha256(evidence)
    return evidence


def _result_evidence(result: ChatResult, index: int, previous_hash: str) -> dict[str, Any]:
    legacy_request = {"name": result.name, "model": result.model_req}
    entry = {
        "index": index,
        "name": redact(result.name),
        "model_req": redact(result.model_req),
        "claim": _redact_value(result.claim),
        "verified": result.verified,
        "status": result.status,
        "latency_ms": result.latency_ms,
        "content_preview": redact(result.content)[:500],
        "request_sha256": result.request_sha256 or _sha256(legacy_request),
        "response_sha256": result.response_sha256
        or hashlib.sha256(redact(result.content).encode("utf-8")).hexdigest(),
        "hash_scope": "client_raw" if result.request_sha256 else "legacy_derived",
        "previous_hash": previous_hash,
    }
    entry["chain_hash"] = _sha256(entry)
    return entry


def create_audit_bundle(result: ScanResult, command: str, exit_code: int) -> dict[str, Any]:
    """生成单 JSON 证据包；manifest 覆盖除自身外的所有字段。"""
    evidence: list[dict[str, Any]] = []
    previous = _GENESIS
    for index, item in enumerate(result.results):
        entry = _result_evidence(item, index, previous)
        evidence.append(entry)
        previous = entry["chain_hash"]
    bundle: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "auditor": {"name": "relay-audit", "version": result.version},
        "timestamps": {
            "started_at": result.started_at,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        },
        "execution": {"command": sanitize_command(command.split()), "exit_code": exit_code},
        "config": _config_evidence(result),
        "verdict": {
            "overall": result.verdict.value,
            "counts": result.verdict_counts,
            "exit_code": exit_code,
        },
        "findings": _redact_value(result.to_dict()["findings"]),
        "evidence": evidence,
        "reference_sources": result.to_dict()["reference_sources"],
        "integrity": {
            "algorithm": "sha256-chain-v1",
            "genesis": _GENESIS,
            "manifest_sha256": "",
        },
    }
    bundle["integrity"]["manifest_sha256"] = _manifest_hash(bundle)
    return bundle


def _manifest_hash(bundle: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in bundle.items() if key != "integrity"}
    integrity = bundle.get("integrity", {})
    unsigned["integrity"] = {
        "algorithm": integrity.get("algorithm"),
        "genesis": integrity.get("genesis"),
        "manifest_sha256": "",
    }
    return _sha256(unsigned)


def export_audit_bundle(result: ScanResult, path: str | Path, command: str, exit_code: int) -> str:
    """原子写出证据包，避免中断留下貌似完整的半文件。"""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle = create_audit_bundle(result, command, exit_code)
    temporary = destination.with_name(destination.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(bundle, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, destination)
    return str(destination)


def verify_audit_bundle(path: str | Path) -> dict[str, Any]:
    """重算配置指纹、每条链哈希和整体 manifest；返回全部错误。"""
    with Path(path).open(encoding="utf-8") as handle:
        bundle = json.load(handle)
    errors: list[str] = []
    if not isinstance(bundle, dict) or bundle.get("schema_version") != _SCHEMA_VERSION:
        return {"ok": False, "errors": ["不支持的证据包 schema"]}
    integrity = bundle.get("integrity")
    evidence = bundle.get("evidence")
    config = bundle.get("config")
    if (
        not isinstance(integrity, dict)
        or not isinstance(evidence, list)
        or not isinstance(config, dict)
    ):
        return {"ok": False, "errors": ["证据包缺少 integrity/evidence/config"]}
    expected_config = _sha256(
        {key: value for key, value in config.items() if key != "fingerprint_sha256"}
    )
    if config.get("fingerprint_sha256") != expected_config:
        errors.append("配置指纹不匹配")
    previous = _GENESIS
    for index, entry in enumerate(evidence):
        if not isinstance(entry, dict) or entry.get("index") != index:
            errors.append(f"证据索引 {index} 非法")
            continue
        if entry.get("previous_hash") != previous:
            errors.append(f"证据索引 {index} 的前向链接不匹配")
        actual = _sha256({key: value for key, value in entry.items() if key != "chain_hash"})
        if entry.get("chain_hash") != actual:
            errors.append(f"证据索引 {index} 的链哈希不匹配")
        previous = entry.get("chain_hash", "")
    if integrity.get("algorithm") != "sha256-chain-v1" or integrity.get("genesis") != _GENESIS:
        errors.append("完整性算法或创世值不匹配")
    if integrity.get("manifest_sha256") != _manifest_hash(bundle):
        errors.append("整体清单哈希不匹配")
    return {"ok": not errors, "errors": errors, "evidence_count": len(evidence)}

"""审计证据包生成、脱敏、完整性复核与 CLI 测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from relay_audit import cli
from relay_audit.audit_bundle import (
    create_audit_bundle,
    export_audit_bundle,
    sanitize_command,
    verify_audit_bundle,
)
from relay_audit.models import ChatResult, Finding, ScanConfig, ScanResult, Severity


def _scan() -> ScanResult:
    passing = ChatResult(
        "基础对话",
        "gpt-4o",
        True,
        10,
        200,
        "gpt-4o",
        "OK",
        {"total_tokens": 2},
        "id-1",
        1_700_000_000,
        request_sha256="a" * 64,
        response_sha256="b" * 64,
    )
    return ScanResult(
        ScanConfig(
            base_url="https://user:secret@api.example.com/v1?key=top-secret",
            model="gpt-4o",
            compare=["claude-3"],
            smoke=True,
        ),
        [Finding(Severity.LOW, "示例", "详情")],
        [passing],
        [],
        "2026-01-01T00:00:00+00:00",
        0.1,
        probe_suite="test-v1",
    )


def test_sanitize_command_masks_keys_and_urls() -> None:
    command = sanitize_command(
        [
            "relay-audit",
            "--key",
            "short-private-key",
            "--base-url",
            "https://user:pw@example.com/v1?api_key=secret#fragment",
            "--key=another-private-key",
        ]
    )
    assert "short-private-key" not in command
    assert "another-private-key" not in command
    assert "pw" not in command and "secret" not in command and "fragment" not in command
    assert "--key [REDACTED]" in command
    assert "--key=[REDACTED]" in command


def test_bundle_generation_and_roundtrip(tmp_path) -> None:
    result = _scan()
    path = export_audit_bundle(
        result, tmp_path / "nested" / "bundle.json", "relay-audit --smoke", 0
    )
    assert not Path(str(path) + ".tmp").exists()
    verified = verify_audit_bundle(path)
    assert verified == {"ok": True, "errors": [], "evidence_count": 1}

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    assert payload["auditor"]["name"] == "relay-audit"
    assert payload["execution"] == {"command": "relay-audit --smoke", "exit_code": 0}
    assert payload["verdict"]["overall"] == "pass"
    assert payload["config"]["smoke"] is True
    assert payload["evidence"][0]["request_sha256"] == "a" * 64
    assert payload["evidence"][0]["response_sha256"] == "b" * 64
    assert payload["evidence"][0]["hash_scope"] == "client_raw"
    assert payload["integrity"]["manifest_sha256"]
    assert "top-secret" not in json.dumps(payload)


def test_bundle_legacy_hash_and_redaction() -> None:
    result = _scan()
    item = result.results[0]
    item.request_sha256 = ""
    item.response_sha256 = ""
    item.content = "token sk-abcdefghijklmnop123456"
    result.findings[0].detail = "key sk-abcdefghijklmnop123456"
    bundle = create_audit_bundle(result, "relay-audit --key short-private-key", 0)
    serialized = json.dumps(bundle)
    assert "short-private-key" not in serialized
    assert "sk-abcdefghijklmnop123456" not in serialized
    assert bundle["evidence"][0]["hash_scope"] == "legacy_derived"
    assert len(bundle["evidence"][0]["request_sha256"]) == 64
    assert len(bundle["evidence"][0]["response_sha256"]) == 64


def _write_tampered(tmp_path, mutate) -> Path:
    path = Path(export_audit_bundle(_scan(), tmp_path / "bundle.json", "relay-audit", 0))
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_tampered_evidence_detected(tmp_path) -> None:
    path = _write_tampered(
        tmp_path, lambda data: data["evidence"][0].update(content_preview="tampered")
    )
    result = verify_audit_bundle(path)
    assert not result["ok"]
    assert any("链哈希" in error for error in result["errors"])
    assert "整体清单哈希不匹配" in result["errors"]


def test_tampered_manifest_and_config_detected(tmp_path) -> None:
    path = _write_tampered(tmp_path, lambda data: data["verdict"].update(overall="fail"))
    assert "整体清单哈希不匹配" in verify_audit_bundle(path)["errors"]

    path2 = _write_tampered(tmp_path, lambda data: data["config"].update(timeout=999))
    assert "配置指纹不匹配" in verify_audit_bundle(path2)["errors"]


def test_tampered_chain_links_and_algorithm_detected(tmp_path) -> None:
    def mutate(data) -> None:
        data["evidence"][0]["index"] = 2
        data["evidence"][0]["previous_hash"] = "f" * 64
        data["integrity"]["algorithm"] = "none"
        data["integrity"]["genesis"] = "f" * 64

    result = verify_audit_bundle(_write_tampered(tmp_path, mutate))
    assert not result["ok"]
    assert any("索引" in error for error in result["errors"])
    assert any("算法" in error for error in result["errors"])


def test_broken_chain_link_detected(tmp_path) -> None:
    result = _scan()
    second = ChatResult("指令遵循", "gpt-4o", True, 10, 200, "gpt-4o", "ZX9-OK!!", {}, "", 0)
    result.results.append(second)
    path = _write_tampered(tmp_path, lambda data: None)  # 先验证辅助函数路径
    assert verify_audit_bundle(path)["ok"]

    export_audit_bundle(result, path, "relay-audit", 0)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["evidence"][1]["previous_hash"] = "f" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert any("前向链接" in error for error in verify_audit_bundle(path)["errors"])


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 99},
        {"schema_version": 1, "integrity": {}, "evidence": [], "config": []},
        {"schema_version": 1, "integrity": {}, "evidence": [1], "config": {}},
    ],
)
def test_structurally_invalid_bundle(tmp_path, payload) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert not verify_audit_bundle(path)["ok"]


def test_cli_verify_bundle_text_json_and_errors(tmp_path, capsys) -> None:
    path = export_audit_bundle(_scan(), tmp_path / "bundle.json", "relay-audit", 0)
    assert cli.main(["--verify-bundle", path]) == 0
    assert "通过" in capsys.readouterr().out

    assert cli.main(["--verify-bundle", path, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    Path(path).write_text("{}", encoding="utf-8")
    assert cli.main(["--verify-bundle", path]) == 1
    assert "失败" in capsys.readouterr().out

    Path(path).write_text("not-json", encoding="utf-8")
    assert cli.main(["--verify-bundle", path]) == 14
    assert "证据包无效" in capsys.readouterr().err

    assert cli.main(["--verify-bundle", str(tmp_path / "missing.json")]) == 14


def test_execute_scan_exports_bundle_and_fails_closed(monkeypatch, tmp_path, capsys) -> None:
    result = _scan()

    async def fake_scan(config):
        return result

    monkeypatch.setattr(cli, "run_scan", fake_scan)
    monkeypatch.setattr("relay_audit.serve.persist_result", lambda *args: None)
    monkeypatch.setattr(cli.os, "environ", {"RELAY_API_KEY": "sk"})
    bundle = tmp_path / "audit.json"
    config = ScanConfig(
        base_url="https://api.example.com", model="gpt-4o", no_html=True, bundle_output=str(bundle)
    )
    ec, _, _ = cli.execute_scan(config)
    assert ec == 0
    assert verify_audit_bundle(bundle)["ok"]
    assert "证据包" in capsys.readouterr().out

    monkeypatch.setattr(
        "relay_audit.audit_bundle.export_audit_bundle",
        lambda *args: (_ for _ in ()).throw(OSError("disk full")),
    )
    config.bundle_output = str(tmp_path / "failure.json")
    ec, _, _ = cli.execute_scan(config)
    assert ec == 14
    assert "审计无效" in capsys.readouterr().err

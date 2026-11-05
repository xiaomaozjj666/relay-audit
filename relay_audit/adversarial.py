"""确定性对抗 fixture 门禁：false acceptance 与诚实端点误报均失败。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analysis import analyze_chat
from .models import ChatResult, ScanConfig, ScanResult, Verdict

FIXTURE_PATH = Path(__file__).with_name("data") / "audit_fixtures.json"


def load_fixture_cases(path: Path | None = None) -> list[dict[str, Any]]:
    """读取并严格校验本地 fixture，拒绝缺字段或未知四态。"""
    fixture_path = path or FIXTURE_PATH
    with fixture_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("不支持的 fixture schema")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("fixture cases 必须是非空列表")
    ids: set[str] = set()
    expected_states = {state.value for state in Verdict}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("fixture case 必须是对象")
        case_id = case.get("id")
        expected = case.get("expected")
        result = case.get("result")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise ValueError("fixture id 缺失或重复")
        if expected not in expected_states or not isinstance(result, dict):
            raise ValueError(f"fixture {case_id} 的 expected/result 非法")
        ids.add(case_id)
    return cases


def evaluate_fixture(case: dict[str, Any]) -> dict[str, Any]:
    """通过真实 ChatResult 与 analyze_chat 路径复核单个 fixture。"""
    values = {
        "latency_ms": 1,
        "status": 200,
        "model_ret": "",
        "content": "",
        "usage": {},
        "raw_id": "",
        "created": 0,
        **case["result"],
    }
    result = ChatResult(**values)
    findings = analyze_chat(result, case.get("kind", "quality"))
    scan = ScanResult(
        config=ScanConfig(base_url="https://fixture.local", model=result.model_req),
        findings=findings,
        results=[result],
        models=[],
        started_at="1970-01-01T00:00:00+00:00",
        duration_s=0.0,
        probe_suite="fixture-v1",
    )
    actual = scan.verdict.value
    expected = case["expected"]
    return {
        "id": case["id"],
        "expected": expected,
        "actual": actual,
        "ok": actual == expected,
        "findings": [finding.title for finding in findings],
    }


def run_fixture_suite(path: Path | None = None) -> dict[str, Any]:
    """执行全部门禁；任一 false acceptance 或误报使汇总失败。"""
    cases = [evaluate_fixture(case) for case in load_fixture_cases(path)]
    failed = [case for case in cases if not case["ok"]]
    return {
        "verdict": Verdict.FAIL.value if failed else Verdict.PASS.value,
        "exit_code": 3 if failed else 0,
        "total": len(cases),
        "failed": len(failed),
        "cases": cases,
    }

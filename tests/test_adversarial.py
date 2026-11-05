"""对抗 fixture 的 false-acceptance 与诚实端点误报门禁。"""

from __future__ import annotations

import json

import pytest

from relay_audit import cli
from relay_audit.adversarial import evaluate_fixture, load_fixture_cases, run_fixture_suite


@pytest.mark.parametrize("case", load_fixture_cases(), ids=lambda case: case["id"])
def test_fixture_verdict_matrix(case) -> None:
    outcome = evaluate_fixture(case)
    assert outcome["ok"], outcome
    assert outcome["actual"] == case["expected"]
    if case["id"].startswith("malicious-"):
        assert outcome["actual"] == "fail", "false acceptance：作恶样本必须失败"
        assert outcome["findings"], "作恶样本必须有可解释检测证据"
    if case["id"].startswith("honest-"):
        assert outcome["actual"] == "pass", "诚实端点不得误判 fail"


def test_fixture_suite_is_deterministic() -> None:
    first = run_fixture_suite()
    second = run_fixture_suite()
    assert first == second
    assert first["verdict"] == "pass"
    assert first["exit_code"] == 0
    assert first["failed"] == 0


def test_claim_alias_does_not_change_verified_verdict() -> None:
    honest = next(case for case in load_fixture_cases() if case["id"] == "honest-basic")
    aliased = next(case for case in load_fixture_cases() if case["id"] == "honest-claim-name-alias")
    assert evaluate_fixture(honest)["actual"] == evaluate_fixture(aliased)["actual"] == "pass"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"schema_version": 2, "cases": []},
        {"schema_version": 1, "cases": []},
        {"schema_version": 1, "cases": ["not-an-object"]},
        {"schema_version": 1, "cases": [{"id": "", "expected": "pass", "result": {}}]},
        {
            "schema_version": 1,
            "cases": [
                {"id": "x", "expected": "unknown", "result": {}},
            ],
        },
        {
            "schema_version": 1,
            "cases": [
                {"id": "x", "expected": "pass", "result": {}},
                {"id": "x", "expected": "pass", "result": {}},
            ],
        },
    ],
)
def test_invalid_fixture_schema_rejected(tmp_path, payload) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_fixture_cases(path)


def test_cli_adversarial_text_and_json(capsys) -> None:
    assert cli.main(["--adversarial"]) == 0
    text = capsys.readouterr().out
    assert "malicious-model-substitution" in text
    assert "11/11 通过" in text

    assert cli.main(["--adversarial", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "pass"
    assert payload["total"] == 11


def test_cli_adversarial_invalid_fixture(monkeypatch, capsys) -> None:
    def broken():
        raise ValueError("bad fixture")

    monkeypatch.setattr("relay_audit.adversarial.run_fixture_suite", broken)
    assert cli.main(["--adversarial"]) == 14
    assert "fixture 无效" in capsys.readouterr().err


def test_cli_adversarial_false_acceptance_exit_three(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "relay_audit.adversarial.run_fixture_suite",
        lambda: {
            "verdict": "fail",
            "exit_code": 3,
            "total": 1,
            "failed": 1,
            "cases": [{"id": "malicious-test", "expected": "fail", "actual": "pass", "ok": False}],
        },
    )
    assert cli.main(["--adversarial"]) == 3
    assert "0/1 通过" in capsys.readouterr().out

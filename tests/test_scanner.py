"""Tests for the scanner."""

from dataclasses import asdict
from relay_audit.scanner import TestCase


def test_testcase_defaults() -> None:
    tc = TestCase(name="defaults", messages=[{"role": "user", "content": "hi"}])
    assert tc.max_tokens == 200
    assert tc.kind == "quality"
    assert tc.response_format is None


def test_testcase_custom_values() -> None:
    tc = TestCase(
        name="custom",
        messages=[{"role": "user", "content": "hello"}],
        kind="quality",
        max_tokens=100,
    )
    d = asdict(tc)
    assert d["name"] == "custom"
    assert d["max_tokens"] == 100
    assert d["kind"] == "quality"


def test_testcase_with_tools() -> None:
    tools = [{"type": "function", "function": {"name": "test", "description": "", "parameters": {}}}]
    tc = TestCase(name="tools", messages=[{"role": "user", "content": "call"}], tools=tools)
    assert tc.tools == tools

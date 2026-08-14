"""Tests for relay_audit package entry points and REPORTS_DIR resolution."""

import runpy

import pytest

import relay_audit
from relay_audit import _default_reports_dir


def test_version_exported() -> None:
    assert isinstance(relay_audit.__version__, str)
    assert relay_audit.__version__ == "2.2.0"
    assert "__version__" in relay_audit.__all__


def test_reports_dir_env_override(monkeypatch, tmp_path) -> None:
    target = tmp_path / "custom" / "reports"
    monkeypatch.setenv("RELAY_AUDIT_REPORTS_DIR", str(target))
    assert _default_reports_dir() == target.resolve()


def test_reports_dir_win32(monkeypatch) -> None:
    monkeypatch.setattr(relay_audit.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\test\AppData\Local")
    assert _default_reports_dir() == (
        relay_audit.Path(r"C:\Users\test\AppData\Local") / "relay-audit" / "reports"
    )


def test_reports_dir_posix(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(relay_audit.sys, "platform", "linux")
    monkeypatch.setattr(relay_audit.Path, "home", lambda: tmp_path)
    assert _default_reports_dir() == tmp_path / ".relay_audit" / "reports"


def test_reports_dir_win32_no_localappdata(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(relay_audit.sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(relay_audit.Path, "home", lambda: tmp_path)
    assert _default_reports_dir() == tmp_path / "relay-audit" / "reports"


def test_main_module_entry(monkeypatch, capsys) -> None:
    """python -m relay_audit 走 __main__ → cli.main。"""
    captured = {}

    def fake_main(argv=None):
        captured["argv"] = argv
        return 7

    monkeypatch.setattr("relay_audit.cli.main", fake_main)
    with pytest.raises(SystemExit) as e:
        runpy.run_module("relay_audit.__main__", run_name="__main__")
    assert e.value.code == 7
    assert captured["argv"] is None

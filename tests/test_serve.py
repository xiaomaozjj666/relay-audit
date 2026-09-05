"""Tests for relay_audit.serve — 含真实 HTTP 服务器与缓存回归."""

import http.client
import json
import re
import threading
from pathlib import Path

import pytest

from relay_audit import serve
from relay_audit.models import ChatResult, Finding, ScanConfig, ScanResult, Severity


def _scan_result(**over) -> ScanResult:
    base = dict(
        config=ScanConfig(base_url="https://api.example.com?x=1&y=2", model="gpt-4o"),
        findings=[Finding(Severity.HIGH, "高危", "detail", "identity")],
        results=[
            ChatResult("基础对话", "gpt-4o", True, 100, 200, "gpt-4o", "ok content", {}, "", 0)
        ],
        models=[],
        started_at="2026-07-11T10:00:00+00:00",
        duration_s=1.0,
    )
    base.update(over)
    return ScanResult(**base)


# ── 路径安全 ────────────────────────────────────────────────


def test_safe_path() -> None:
    assert serve._safe_path("a.html") == "a.html"
    assert serve._safe_path("../../etc/passwd") == "passwd"
    assert serve._safe_path("a/b/c.json") == "c.json"
    assert serve._safe_path("") == ""


def test_resolve_inside(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    (tmp_path / "ok.html").write_text("x")
    assert serve._resolve_inside("ok.html") is not None
    assert serve._resolve_inside("../x") is None
    assert serve._resolve_inside("missing.html") is None
    assert serve._resolve_inside("dir/../ok.html") is not None


def test_resolve_inside_escape_branch(monkeypatch, tmp_path) -> None:
    """_safe_path 被绕过（如符号链接场景）时 ValueError 分支返回 None。"""
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(serve, "_safe_path", lambda name: "../escape")
    assert serve._resolve_inside("whatever") is None


# ── persist_result ──────────────────────────────────────────


def test_persist_result_redacts_and_hashes(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    r = _scan_result(
        findings=[
            Finding(
                Severity.HIGH, "高危", "detail", "identity", reason="key sk-abcdefghijklmnop123456"
            )
        ],
        results=[
            ChatResult(
                "基础对话",
                "gpt-4o",
                True,
                100,
                200,
                "gpt-4o",
                "echo sk-abcdefghijklmnop123456",
                {},
                "",
                0,
            )
        ],
    )
    path = serve.persist_result(r, "https://api.example.com?x=1&y=2")
    name = str(path).replace("\\", "/").split("/")[-1]
    assert re.match(r"scan_\d{8}_\d{6}_[0-9a-f]{8}_", name)
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = json.dumps(data, ensure_ascii=False)
    assert "sk-abcdefghijklmnop123456" not in raw
    assert "[REDACTED]" in raw
    assert data["base_url"] == "https://api.example.com?x=1&y=2"
    assert data["summary"]["risk_level"] == "HIGH"
    assert data["summary"]["tests_total"] == 1


def test_persist_result_distinct_urls(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    r = _scan_result()
    serve.persist_result(r, "https://api.example.com/same-prefix-aaaa")
    serve.persist_result(r, "https://api.example.com/same-prefix-bbbb")
    files = list(tmp_path.glob("scan_*.json"))
    assert len(files) == 2  # 哈希避免碰撞覆盖


# ── 列表解析 ────────────────────────────────────────────────


def test_list_json_reports_skips_corrupt(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    (tmp_path / "scan_20260101_000000_bad.json").write_text("{not json")
    assert serve.list_json_reports() == []


def test_list_json_reports_missing_dir(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path / "nope")
    assert serve.list_json_reports() == []
    assert serve.list_html_reports() == []


def test_list_html_reports_unescape_url(tmp_path, monkeypatch) -> None:
    """回归 M4：含 & 的 base_url 不得双重转义。"""
    from relay_audit.reporter import generate_html

    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    r = _scan_result()
    r.config.base_url = "https://api.example.com/a?b=1&c=2"
    html = generate_html(r)
    (tmp_path / "relay_report_20260711_100000.html").write_text(html, encoding="utf-8")
    reports = serve.list_html_reports()
    assert reports[0]["base_url"] == "https://api.example.com/a?b=1&amp;c=2"
    assert "&amp;amp;" not in reports[0]["base_url"]


def test_list_html_reports_medium_risk(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    (tmp_path / "relay_report_20260711_100000.html").write_text(
        '<div class="url-text">https://m</div><span class="risk-level">中风险</span>',
        encoding="utf-8",
    )
    reports = serve.list_html_reports()
    assert reports[0]["risk_level"] == "MEDIUM"


def test_list_html_reports_read_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    (tmp_path / "relay_report_20260711_100000.html").write_text("<html></html>", encoding="utf-8")

    def boom(self, **kw):
        raise OSError("denied")

    monkeypatch.setattr("pathlib.Path.read_text", boom)
    assert serve.list_html_reports() == []


def test_list_reports_merged_sorted(tmp_path, monkeypatch) -> None:
    """按 mtime 排序（HTML/JSON 时间戳格式不同，不能字符串比较）。"""
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    # 先写 JSON（mtime 更旧），再写 HTML（mtime 更新）→ 列表应 HTML 在前
    jf = tmp_path / "scan_20260710_100000_abc.json"
    jf.write_text(
        '{"timestamp":"20260710_100000","base_url":"https://b","summary":{"risk_level":"LOW"}}',
        encoding="utf-8",
    )
    hf = tmp_path / "relay_report_20260711_100000.html"
    hf.write_text(
        '<div class="url-text">https://a</div><span class="risk-level">低风险</span>'
        '<span class="stat-pill-num">1</span><span class="stat-pill-num">2</span>'
        '<span class="stat-pill-num">3</span><span class="stat-pill-num">4/5</span>',
        encoding="utf-8",
    )
    # 显式设置 mtime，避免同一文件系统时间戳粒度导致相等
    import os

    os.utime(jf, (1700000000, 1700000000))
    os.utime(hf, (1700000100, 1700000100))
    reports = serve.list_reports()
    # JSON 报告时间戳展示格式与 HTML 一致
    assert reports[-1]["timestamp"] == "2026-07-10 10:00:00"
    assert [r["type"] for r in reports] == ["html", "json"]
    assert reports[0]["mtime"] > reports[1]["mtime"]


# ── 缓存 ───────────────────────────────────────────────────


def _reset_cache(monkeypatch):
    monkeypatch.setattr(serve, "_reports_cache", (0, frozenset(), []))


def test_list_reports_cached_invalidation(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    _reset_cache(monkeypatch)
    assert serve.list_reports_cached() == []
    # 缓存命中（无变化）
    assert serve.list_reports_cached() == []

    f = tmp_path / "scan_20260101_000000_abc.json"
    f.write_text('{"timestamp":"t1","base_url":"https://x","summary":{}}')
    assert len(serve.list_reports_cached()) == 1

    # 删除后缓存必须失效（回归 M3）
    f.unlink()
    assert serve.list_reports_cached() == []

    # 修改（mtime 更新）后失效
    f.write_text('{"timestamp":"t2","base_url":"https://y","summary":{}}')
    reports = serve.list_reports_cached()
    assert reports[0]["base_url"] == "https://y"


def test_list_reports_cached_oserror(tmp_path, monkeypatch) -> None:
    class FakeDir:
        def is_dir(self):
            return True

        def iterdir(self):
            raise OSError("denied")

        def glob(self, pattern):
            return []

    monkeypatch.setattr(serve, "REPORTS_DIR", FakeDir())
    _reset_cache(monkeypatch)
    assert serve.list_reports_cached() == []


# ── HTTP 服务器 ─────────────────────────────────────────────


@pytest.fixture()
def http_server(tmp_path, monkeypatch):
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    _reset_cache(monkeypatch)
    server = serve.ThreadingHTTPServer(("127.0.0.1", 0), serve.ReportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield port, tmp_path
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _get(port: int, path: str) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def test_server_index(http_server) -> None:
    port, _ = http_server
    status, body = _get(port, "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "Relay Audit 报告列表" in text
    assert "↻ 刷新" in text  # 刷新入口
    assert 'id="filter"' in text  # 搜索过滤框
    assert "按目标 / 风险 / 类型过滤" in text


def test_server_reports_api_and_report(http_server) -> None:
    port, tmp = http_server
    (tmp / "scan_20260101_000000_abc.json").write_text(
        '{"timestamp":"20260101","base_url":"https://x","summary":{"risk_level":"LOW"}}',
        encoding="utf-8",
    )
    status, body = _get(port, "/api/reports")
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert len(data) == 1 and data[0]["type"] == "json"

    status, body = _get(port, "/api/report/scan_20260101_000000_abc.json")
    assert status == 200
    assert json.loads(body.decode("utf-8"))["base_url"] == "https://x"

    status, _ = _get(port, "/api/report/missing.json")
    assert status == 404
    status, _ = _get(port, "/api/report/notjson.txt")
    assert status == 404


def test_server_html_routes(http_server) -> None:
    port, tmp = http_server
    (tmp / "relay_report_20260101_000000.html").write_text("<html>hi</html>", encoding="utf-8")
    status, body = _get(port, "/html/relay_report_20260101_000000.html")
    assert status == 200 and body == b"<html>hi</html>"
    status, _ = _get(port, "/relay_report_20260101_000000.html")
    assert status == 200
    status, _ = _get(port, "/nope.html")
    assert status == 404


def test_server_traversal_blocked(http_server) -> None:
    port, _ = http_server
    for path in (
        "/html/../../etc/passwd",
        "/html/..%2F..%2Fetc%2Fpasswd",
        "/api/report/../secret.json",
        "/api/report/%2e%2e/secret.json",
    ):
        status, _ = _get(port, path)
        assert status == 404, path


def test_server_fallback_static(http_server) -> None:
    port, tmp = http_server
    (tmp / "data.txt").write_text("hello", encoding="utf-8")
    status, body = _get(port, "/data.txt")
    assert status == 200 and body == b"hello"
    status, _ = _get(port, "/missing.txt")
    assert status == 404
    status, _ = _get(port, "/favicon.ico")
    assert status == 404


def test_server_html_extension_guard(http_server) -> None:
    port, tmp = http_server
    (tmp / "evil.htm").write_text("x")
    status, _ = _get(port, "/html/evil.htm")
    assert status == 200


def test_server_io_error_returns_500(http_server, monkeypatch) -> None:
    port, tmp = http_server
    (tmp / "relay_report_20260101_000000.html").write_text("<html></html>", encoding="utf-8")
    (tmp / "scan_20260101_000000_abc.json").write_text("{}", encoding="utf-8")

    def boom(self, *a, **k):
        raise OSError("io denied")

    monkeypatch.setattr("pathlib.Path.read_bytes", boom)
    status, _ = _get(port, "/html/relay_report_20260101_000000.html")
    assert status == 500
    status, _ = _get(port, "/api/report/scan_20260101_000000_abc.json")
    assert status == 500


# ── run_server ──────────────────────────────────────────────


def test_run_server(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    started = {}

    class FakeServer:
        def __init__(self, addr, handler):
            started["addr"] = addr
            started["handler"] = handler

        def serve_forever(self):
            raise KeyboardInterrupt()

        def server_close(self):
            started["closed"] = True

    monkeypatch.setattr(serve, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(serve.webbrowser, "open", lambda url: started.update(opened=url))
    serve.run_server(1234, open_browser=True)
    assert started["addr"] == ("127.0.0.1", 1234)
    assert started["handler"] is serve.ReportHandler
    assert started["opened"] == "http://127.0.0.1:1234"
    assert started["closed"] is True


def test_run_server_no_browser(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path)
    started = {}

    class FakeServer:
        def __init__(self, addr, handler):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt()

        def server_close(self):
            started["closed"] = True

    monkeypatch.setattr(serve, "ThreadingHTTPServer", FakeServer)
    serve.run_server(4321, open_browser=False)
    assert started["closed"] is True

"""Lightweight HTTP server to browse past scan reports."""

from __future__ import annotations

import json
import os
import webbrowser
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def persist_result(result: Any, base_url: str) -> str:
    """Save scan result as JSON to reports/ and return the file path."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = base_url.replace("://", "_").replace("/", "_").replace(":", "_")[:40]
    filename = f"scan_{ts}_{safe_url}.json"
    filepath = reports_dir / filename

    data = {
        "timestamp": ts,
        "base_url": base_url,
        "summary": {
            "risk_level": result.risk_level,
            "high_count": result.high_count,
            "total_findings": len(result.findings),
            "tests_passed": sum(1 for r in result.results if r.ok),
            "tests_total": len(result.results),
        },
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "title": f.title,
                "reason": f.reason,
            }
            for f in result.findings
        ],
        "results": [
            {
                "name": r.name,
                "ok": r.ok,
                "latency_ms": r.latency_ms,
                "status": r.status,
                "content_preview": (r.content or "")[:200],
            }
            for r in result.results
        ],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return str(filepath)


def list_reports() -> list[dict]:
    """Return sorted list of past scan reports."""
    if not reports_dir.is_dir():
        return []
    reports = []
    for f in sorted(reports_dir.glob("scan_*.json"), reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            reports.append({
                "file": f.name,
                "timestamp": data.get("timestamp", ""),
                "base_url": data.get("base_url", ""),
                "risk_level": data.get("summary", {}).get("risk_level", ""),
                "findings": data.get("summary", {}).get("total_findings", 0),
                "tests_passed": data.get("summary", {}).get("tests_passed", 0),
                "tests_total": data.get("summary", {}).get("tests_total", 0),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return reports


class ReportHandler(SimpleHTTPRequestHandler):
    """Serves JSON responses for report browsing."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(reports_dir), **kwargs)

    def do_GET(self) -> None:
        if self.path == "/":
            self._serve_index()
        elif self.path.startswith("/api/reports"):
            self._serve_reports_api()
        elif self.path.startswith("/api/report/"):
            name = self.path.removeprefix("/api/report/")
            self._serve_single_report(name)
        else:
            super().do_GET()

    def _serve_index(self) -> None:
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Relay Audit Reports</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font:14px/1.5 -apple-system,sans-serif;background:#f5f6f8;padding:30px;max-width:800px;margin:auto}
h1{font-size:20px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06)}
th{background:#f8f9fc;padding:8px 12px;text-align:left;font-size:12px;color:#888;border-bottom:1px solid #eee}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;font-size:13px}
tr:last-child td{border-bottom:none}
a{color:#1a73e8;text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff}
.badge-HIGH{background:#e74c3c}.badge-MEDIUM{background:#f39c12}.badge-LOW{background:#27ae60}
.footer{text-align:center;color:#bbb;font-size:11px;margin-top:16px}
</style></head>
<body><h1>📋 Relay Audit Reports</h1>
<div id="app">Loading...</div>
<script>
fetch('/api/reports').then(r=>r.json()).then(data=>{
  const html=data.length?'<table><tr><th>Time</th><th>Target</th><th>Risk</th><th>Findings</th><th>Tests</th></tr>'+
    data.map(r=>'<tr><td>'+r.timestamp+'</td><td><a href="/api/report/'+r.file+'">'+r.base_url+'</a></td>'+
    '<td><span class="badge badge-'+r.risk_level+'">'+r.risk_level+'</span></td>'+
    '<td>'+r.findings+'</td><td>'+r.tests_passed+'/'+r.tests_total+'</td></tr>').join('')+
    '</table>':'<p>No reports yet. Run <code>relay-audit --base-url https://...</code> first.</p>';
  document.getElementById('app').innerHTML=html;
});
</script>
<div class="footer">Relay Audit</div></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _serve_reports_api(self) -> None:
        data = json.dumps(list_reports(), ensure_ascii=False)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(data.encode("utf-8"))

    def _serve_single_report(self, name: str) -> None:
        filepath = reports_dir / name
        if not filepath.is_file():
            self.send_response(404)
            self.end_headers()
            return
        try:
            data = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.send_response(500)
            self.end_headers()


def run_server(port: int = 8080, open_browser: bool = True) -> None:
    """Start the report viewer server."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    server = HTTPServer(("127.0.0.1", port), ReportHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"  [i] Report server started at {url}")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [i] Server stopped.")
        server.server_close()

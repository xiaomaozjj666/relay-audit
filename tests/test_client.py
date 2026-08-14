"""Tests for relay_audit.client — ApiClient 全路径覆盖."""

import asyncio
import json

import httpx

from relay_audit.client import ApiClient, _parse_chat_response


def _mk_client(handler, timeout: float = 5) -> ApiClient:
    transport = httpx.MockTransport(handler)
    hc = httpx.AsyncClient(transport=transport, base_url="https://fake.test")
    client = ApiClient.__new__(ApiClient)
    client.base = "https://fake.test"
    client.headers = {}
    client.timeout = timeout
    client._client = hc
    return client


def _run(coro):
    return asyncio.run(coro)


# ── __init__ / 上下文管理 ───────────────────────────────────


def test_init_normalizes_base_url() -> None:
    c = ApiClient("https://api.example.com/v1", "sk-abc")
    assert c.base == "https://api.example.com"
    assert c.headers["Authorization"] == "Bearer sk-abc"
    assert c.headers["Content-Type"] == "application/json"
    assert c.timeout == 60


def test_aenter_aexit() -> None:
    async def _run():
        client = ApiClient("https://api.example.com/v1", "k", 30)
        async with client as c:
            assert c._client is not None
        assert client._client is not None
        await client._client.aclose()

    asyncio.run(_run())


# ── _parse_chat_response ────────────────────────────────────


def test_parse_success() -> None:
    resp = httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{"message": {"content": "hello"}}],
            "usage": {"total_tokens": 10},
        },
    )
    r = _parse_chat_response("gpt-4o", 200, resp, 1.5)
    assert r.ok
    assert r.content == "hello"
    assert r.model_ret == "gpt-4o"
    assert r.raw_id == "chatcmpl-1"
    assert r.created == 1700000000
    assert r.usage == {"total_tokens": 10}
    assert r.latency_ms == 1500
    assert r.error == ""


def test_parse_tool_calls() -> None:
    resp = httpx.Response(
        200,
        json={
            "choices": [{"message": {"tool_calls": [{"function": {"name": "f"}}]}}],
        },
    )
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.ok
    assert "f" in r.content


def test_parse_error_body() -> None:
    resp = httpx.Response(500, json={"error": {"message": "boom"}})
    r = _parse_chat_response("m", 500, resp, 0.1)
    assert not r.ok
    assert r.status == 500
    assert r.error == "HTTP 500"
    assert "boom" in r.content


def test_parse_invalid_json() -> None:
    resp = httpx.Response(200, text="not json {{{")
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.ok
    assert r.content == ""


def test_parse_non_dict_and_empty() -> None:
    resp = httpx.Response(200, text="[]")
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.ok and r.content == ""
    resp2 = httpx.Response(200, text="")
    r2 = _parse_chat_response("m", 200, resp2, 0.1)
    assert r2.ok and r2.content == ""


def test_parse_weird_choices() -> None:
    resp = httpx.Response(200, json={"choices": "nope", "usage": "nope"})
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.ok
    assert r.usage == {}
    assert r.content == ""


# ── chat() ──────────────────────────────────────────────────


def test_chat_body_and_success() -> None:
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    r = _run(
        _mk_client(handler).chat(
            "m", [{"role": "user", "content": "hi"}], max_tokens=50, stream=True
        )
    )
    assert r.ok and r.content == "ok"
    assert captured["body"]["stream"] is True
    assert captured["body"]["max_tokens"] == 50
    assert captured["body"]["temperature"] == 0


def test_chat_response_format_and_tools() -> None:
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    r = _run(
        _mk_client(handler).chat(
            "m",
            [{"role": "user", "content": "hi"}],
            response_format={"type": "json_object"},
            tools=[{"type": "function", "function": {"name": "f"}}],
        )
    )
    assert r.ok
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert captured["body"]["tool_choice"] == "auto"


def test_chat_retry_500_then_success() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls < 2:
            return httpx.Response(500, json={"error": "internal"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "ok"
    assert calls == 2


def test_chat_500_exhausts_retries() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(500, json={"error": "internal"})

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 500
    assert calls == 3  # 初始 + 2 次重试


def test_chat_429_no_retry() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={"error": "rate"})

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 429
    assert calls == 1


def test_chat_retry_disabled() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(500, json={"error": "internal"})

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}], retry=False))
    assert not r.ok
    assert calls == 1


def test_chat_timeout() -> None:
    async def handler(request):
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    r = _run(_mk_client(handler, timeout=0.01).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 0
    assert "timeout" in r.error


def test_chat_generic_exception() -> None:
    def handler(request):
        raise RuntimeError("boom")

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 0
    assert "RuntimeError" in r.error


def test_chat_http_status_error() -> None:
    """httpx.HTTPStatusError 分支（正常路径不会触发，手动抛出覆盖）。"""

    def handler(request):
        req = httpx.Request("POST", "https://fake.test/v1/chat/completions")
        raise httpx.HTTPStatusError(
            "boom",
            request=req,
            response=httpx.Response(503, json={"error": {"message": "svc down"}}),
        )

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 503
    assert "svc down" in r.content


# ── chat_stream() ───────────────────────────────────────────


def test_chat_stream_success() -> None:
    def handler(request):
        body = (
            b'data: {"id":"1","created":1700000000,"model":"gpt-4o",'
            b'"choices":[{"delta":{"content":"Hel"}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
            b'data: {"choices":[{"delta":{}}],"usage":{"total_tokens":5}}\n\n'
            b"data: [DONE]\n\n"
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok
    assert r.content == "Hello"
    assert r.streaming
    assert r.model_ret == "gpt-4o"
    assert r.raw_id == "1"
    assert r.created == 1700000000
    assert r.usage == {"total_tokens": 5}


def test_chat_stream_skips_bad_json() -> None:
    body = b'data: not-json\n\ndata: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n'

    def handler(request):
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "x"


def test_chat_stream_non_2xx() -> None:
    def handler(request):
        return httpx.Response(500, text="boom")

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 500


def test_chat_stream_timeout() -> None:
    """MockTransport 不强制超时，用 stub stream 直接触发 TimeoutError 分支。"""

    class TimeoutStreamResp:
        status_code = 200

        async def aiter_lines(self):
            raise asyncio.TimeoutError()
            yield  # 使函数成为 async generator（async for 需要）

    class TimeoutStreamCM:
        async def __aenter__(self):
            return TimeoutStreamResp()

        async def __aexit__(self, *a):
            pass

    class SlowClient:
        def stream(self, *a, **k):
            return TimeoutStreamCM()

    client = ApiClient.__new__(ApiClient)
    client.base = "https://fake.test"
    client.headers = {}
    client.timeout = 1
    client._client = SlowClient()
    r = asyncio.run(client.chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert "timeout" in r.error.lower()


def test_chat_stream_exception() -> None:
    async def handler(request):
        raise RuntimeError("stream boom")

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert "RuntimeError" in r.error


# ── list_models / concurrent_chat ───────────────────────────


def test_list_models_success() -> None:
    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "gpt-4o"}]}, headers={"server": "nginx"})

    status, models, parsed, lat, headers = _run(_mk_client(handler).list_models())
    assert status == 200
    assert models == [{"id": "gpt-4o"}]
    assert parsed["data"] == [{"id": "gpt-4o"}]
    assert lat >= 0
    assert headers["server"] == "nginx"


def test_list_models_weird_and_error() -> None:
    def handler(request):
        return httpx.Response(200, json={"data": "nope"})

    status, models, parsed, _, _ = _run(_mk_client(handler).list_models())
    assert status == 200
    assert models == []
    assert parsed == {"data": "nope"}

    def handler2(request):
        raise RuntimeError("net down")

    status, models, parsed, _, headers = _run(_mk_client(handler2).list_models())
    assert status == 0
    assert models == []
    assert "RuntimeError" in parsed["error"]
    assert headers == {}


def test_list_models_empty_body() -> None:
    def handler(request):
        return httpx.Response(200, text="")

    status, models, parsed, _, _ = _run(_mk_client(handler).list_models())
    assert status == 200
    assert models == []
    assert parsed == {}


def test_concurrent_chat() -> None:
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    results = _run(_mk_client(handler).concurrent_chat(3, "m", [{"role": "user", "content": "hi"}]))
    assert len(results) == 3
    assert all(r.ok for r in results)


def test_concurrent_chat_errors_captured() -> None:
    # chat() 内部吞掉所有异常 → gather 不会抛，返回失败 ChatResult
    def handler(request):
        raise RuntimeError("boom")

    results = _run(_mk_client(handler).concurrent_chat(2, "m", [{"role": "user", "content": "hi"}]))
    assert len(results) == 2
    assert all(not r.ok for r in results)

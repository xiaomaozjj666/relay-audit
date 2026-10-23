"""网络层健壮性回归 — H1 usage 安全化 / M2 SSE 规范 / M3 非 2xx 流 / L5 超限 / L2 超时分支.

威胁模型：被检测的中转站是恶意的 — 所有畸形输入不得透传导致下游崩溃。
"""

import asyncio

import httpx
import pytest
from relay_audit import client as client_module
from relay_audit.client import (
    ApiClient,
    _extract_error_body,
    _parse_chat_response,
    _safe_int,
    _sanitize_usage,
    _SseAccumulator,
)


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


# ── H1：_safe_int 语义全表 ───────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (123, 123),
        (-456, -456),
        (0, 0),
        (10**18, 10**18),  # 巨大数直通
        (True, 0),  # bool 拒绝
        (False, 0),
        ("123", 123),
        ("+123", 123),
        ("-456", -456),
        (" 789 ", 789),  # 首尾空白容忍
        ("-999999999999", -999999999999),  # 带负号的巨大数字符串
        ("12a", 0),  # str 非数字
        ("1.5", 0),  # 非纯数字字符串
        ("", 0),
        ("--5", 0),
        ("+-5", 0),
        (3.9, 3),  # float 截断
        (-3.9, -3),
        (0.0, 0),
        (1e18, 10**18),  # float 巨大数
        (float("nan"), 0),
        (float("inf"), 0),
        (float("-inf"), 0),
        (None, 0),
        ([1, 2], 0),
        ({"a": 1}, 0),
        ((), 0),
    ],
)
def test_safe_int_matrix(value, expected) -> None:
    out = _safe_int(value)
    assert isinstance(out, int) and not isinstance(out, bool)
    assert out == expected


# ── H1：usage 数值字段畸形矩阵（逐字段）────────────────────


WEIRD_TOKEN_VALUES = [
    ("123", 123),  # str 数字
    ("abc", 0),  # str 非数字
    (None, 0),
    ([1], 0),
    ({"x": 1}, 0),
    (True, 0),  # bool
    (False, 0),
    (-5, -5),  # 负数
    (10**18, 10**18),  # 巨大数
    ("-7", -7),  # 带符号字符串
    (3.7, 3),  # float
    (float("nan"), 0),
    ("", 0),
]


@pytest.mark.parametrize(
    "field", ["prompt_tokens", "completion_tokens", "total_tokens"]
)
@pytest.mark.parametrize("value_expected", WEIRD_TOKEN_VALUES, ids=str)
def test_sanitize_usage_matrix(field, value_expected) -> None:
    value, expected = value_expected
    out = _sanitize_usage({field: value})
    assert isinstance(out[field], int)
    assert not isinstance(out[field], bool)
    assert out[field] == expected


def test_sanitize_usage_keeps_non_standard_fields() -> None:
    """三个标准计数字段外的字段（如嵌套 details）原样保留，不误伤。"""
    usage = {
        "prompt_tokens": "8",
        "prompt_tokens_details": {"cached_tokens": "1"},
        "extra": "note",
    }
    out = _sanitize_usage(usage)
    assert out["prompt_tokens"] == 8
    assert out["prompt_tokens_details"] == {"cached_tokens": "1"}
    assert out["extra"] == "note"


def test_parse_chat_response_malformed_usage() -> None:
    """H1 集成：畸形 usage / created 落袋前安全化，不再透传字符串 token 数。"""
    resp = httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {
                "prompt_tokens": "12",
                "completion_tokens": "not-a-number",
                "total_tokens": None,
            },
            "created": "1700000000",
        },
    )
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.ok
    assert r.usage["prompt_tokens"] == 12
    assert r.usage["completion_tokens"] == 0
    assert r.usage["total_tokens"] == 0
    assert r.created == 1700000000
    # tokens_per_second 不再因字符串 total_tokens 抛 TypeError
    assert isinstance(r.tokens_per_second, float)


def test_parse_chat_response_usage_not_dict() -> None:
    """usage 本身非 dict → 空字典（既有行为保持）。"""
    resp = httpx.Response(
        200, json={"choices": [{"message": {"content": "x"}}], "usage": "nope"}
    )
    r = _parse_chat_response("m", 200, resp, 0.1)
    assert r.usage == {}


# ── M2：SSE 解析规范缺陷 ────────────────────────────────────


def test_sse_accumulator_unit() -> None:
    acc = _SseAccumulator()
    assert acc.feed("data: 1") is None  # 事件未闭合
    assert acc.feed("data:2") is None  # 无空格前缀也是合法 data 行
    assert acc.feed("") == "1\n2"  # 空行闭合事件，双 data 以 \n 拼接
    assert acc.feed("event: x") is None  # 非 data 行忽略
    assert acc.feed(": ping") is None  # 注释行忽略
    assert acc.feed("") is None  # 无 data 行的事件块 → None
    assert acc.feed("data: tail") is None
    assert acc.flush() == "tail"  # 流结束冲刷未闭合的尾部事件
    assert acc.flush() is None  # 再次冲刷为空


def test_stream_data_prefix_without_space() -> None:
    """M2-1：`data:` 无空格（SSE 规范合法）不再被静默丢弃。"""

    def handler(request):
        body = b'data:{"choices":[{"delta":{"content":"X"}}]}\n\ndata:[DONE]\n\n'
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "X"
    assert r.error == ""


def test_stream_data_prefix_multiple_spaces() -> None:
    """`data:  x`（两个空格）：剥一个空格后 payload 前导仍留一个空格。"""

    def handler(request):
        body = b'data: {"choices":[{"delta":{"content":"Y"}}]}\n\ndata: [DONE]\n\n'
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "Y"


def test_stream_multiline_data_event() -> None:
    """M2-2：多行 data 事件按规范以 \n 拼接后再解析（拼接点在 JSON 结构空白处）。"""

    def handler(request):
        body = (
            b'data: {"choices":[{"delta":{"content":"He"}}],\n'
            b'data: "usage":{"total_tokens":5}}\n\n'
            b"data: [DONE]\n\n"
        )
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.content == "He"
    assert r.usage["total_tokens"] == 5
    assert r.error == ""


def test_stream_truncated_without_done() -> None:
    """M2-3：截断流（无 [DONE] 无 finish_reason）→ error 打「流未正常终止」告警。"""

    def handler(request):
        body = b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok  # 2xx 仍判通过，但携带告警标记
    assert r.content == "partial"  # content 保持原样
    assert "流未正常终止" in r.error


def test_stream_finish_reason_counts_as_termination() -> None:
    """finish_reason 终止信号足以避免截断告警（部分实现不发 [DONE]）。"""

    def handler(request):
        body = (
            b'data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
        )
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.content == "ok"
    assert r.error == ""


def test_stream_tail_event_without_trailing_blank() -> None:
    """流结束但尾部事件未以空行收尾 → 冲刷后仍解析（不丢最后一段内容）。"""

    def handler(request):
        body = (
            b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"b"}}]}\n'
        )
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.content == "ab"
    assert "流未正常终止" in r.error  # 无 [DONE]/finish_reason


def test_stream_normal_done_no_warning() -> None:
    """正常 [DONE] 终止 → 无任何告警（回归锁定）。"""

    def handler(request):
        body = b'data: {"choices":[{"delta":{"content":"a"}}]}\n\ndata: [DONE]\n\n'
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "a"
    assert r.error == ""


def test_stream_crlf_mixed_line_endings() -> None:
    """CRLF 与 LF 混用的行结束符都能正确分事件。"""

    def handler(request):
        body = (
            b'data: {"choices":[{"delta":{"content":"A"}}]}\r\n\r\n'
            b'data: {"choices":[{"delta":{"content":"B"}}]}\n\n'
            b"data: [DONE]\r\n\r\n"
        )
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.content == "AB"
    assert r.error == ""


def test_stream_usage_fields_sanitized() -> None:
    """H1 流式对齐：SSE usage 块中的字符串 token 数同样安全化。"""

    def handler(request):
        body = b'data: {"usage":{"prompt_tokens":"7","total_tokens":9}}\n\ndata: [DONE]\n\n'
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.usage == {"prompt_tokens": 7, "total_tokens": 9}


def test_stream_json_array_payload_ignored() -> None:
    """JSON 非 dict 载荷（如 list）→ 忽略而非崩溃（旧代码会 AttributeError）。"""

    def handler(request):
        body = b"data: [1,2]\n\ndata: [DONE]\n\n"
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == ""
    assert r.error == ""


def test_stream_non_string_delta_ignored() -> None:
    """delta.content 为非字符串（恶意构造）→ 跳过而非 TypeError 崩掉整个流。"""

    def handler(request):
        body = (
            b'data: {"choices":[{"delta":{"content":{"evil":1}}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
            b"data: [DONE]\n\n"
        )
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok and r.content == "ok"


# ── M3：非 2xx 流式响应的错误体提取 ─────────────────────────


def test_stream_non_2xx_json_error_body() -> None:
    """M3：流式 401 的 JSON 错误体不再被 data 过滤器整体丢弃。"""

    def handler(request):
        return httpx.Response(401, json={"error": {"message": "Invalid API key"}})

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 401
    assert "HTTP 401" in r.error
    assert "Invalid API key" in r.error
    assert "Invalid API key" in r.content  # 对齐非流式的 content 提取语义


def test_stream_non_2xx_plain_text() -> None:
    """非 2xx 纯文本错误体 → 原文前 200 字符进 error。"""

    def handler(request):
        return httpx.Response(503, text="service unavailable")

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.error == "HTTP 503: service unavailable"


def test_stream_non_2xx_empty_body() -> None:
    """非 2xx 空 body → error 至少含 HTTP {status}。"""

    def handler(request):
        return httpx.Response(502, content=b"")

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.error == "HTTP 502"


def test_stream_non_2xx_string_error_and_message() -> None:
    """error 为字符串 / 顶层 message 字段两种形态都能提取。"""

    def h1(request):
        return httpx.Response(429, json={"error": "rate limited"})

    def h2(request):
        return httpx.Response(400, json={"message": "bad request"})

    r1 = _run(_mk_client(h1).chat_stream("m", []))
    assert "HTTP 429" in r1.error and "rate limited" in r1.error
    r2 = _run(_mk_client(h2).chat_stream("m", []))
    assert "HTTP 400" in r2.error and "bad request" in r2.error


def test_extract_error_body_unit() -> None:
    assert _extract_error_body(b'{"error":{"message":"boom"}}') == "boom"
    assert _extract_error_body(b'{"message":"m"}') == "m"
    assert _extract_error_body(b'{"error":"str err"}') == "str err"
    assert (
        _extract_error_body(b'{"error":{"code":5}}') == '{"error":{"code":5}}'
    )  # 无 message → 原文
    assert _extract_error_body(b"plain text") == "plain text"
    assert _extract_error_body(b"") == ""
    long_msg = b"x" * 300
    assert (
        len(_extract_error_body(b'{"error":{"message":"' + long_msg + b'"}}')) == 200
    )  # 截断
    assert len(_extract_error_body(long_msg)) == 200
    # error.message 非 str → 回退原文
    assert (
        _extract_error_body(b'{"error":{"message":123}}') == '{"error":{"message":123}}'
    )


# ── L5：响应体大小上限 ──────────────────────────────────────


def test_stream_response_size_cap(monkeypatch) -> None:
    """L5：超长流式响应 → 停止读取、部分内容保留、error 注明超限截断。"""
    monkeypatch.setattr(client_module, "_MAX_RESPONSE_BYTES", 1024)

    def handler(request):
        line = b'data: {"choices":[{"delta":{"content":"' + b"a" * 40 + b'"}}]}'
        body = (line + b"\n\n") * 40  # 约 3.5KB > 1024 上限
        return httpx.Response(200, content=body)

    r = _run(_mk_client(handler).chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert r.ok  # 已收到的内容仍在
    assert 0 < len(r.content) < 40 * 41  # 明显少于全量（提前停止读取）
    assert "响应超限" in r.error


def test_chat_content_length_precap() -> None:
    """L5：非流式 Content-Length 预检 — 头声明超限直接拒绝，不做 JSON 解析。"""

    def handler(request):
        return httpx.Response(
            200,
            content=b'{"choices":[{"message":{"content":"x"}}]}',
            headers={"content-length": str(20 * 1024 * 1024)},
        )

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.status == 200
    assert "响应体超限" in r.error


def test_chat_oversized_body_postcap() -> None:
    """L5：头缺失时读入后兜底检查 body 大小超限 → 拒绝解析。"""

    def handler(request):
        big = b'{"padding":"' + b"a" * (11 * 1024 * 1024) + b'"}'
        return httpx.Response(200, content=big)

    r = _run(_mk_client(handler).chat("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert "响应体超限" in r.error


def test_list_models_oversize() -> None:
    """L5：模型列表响应超限 → 空列表 + error 说明，不解析。"""

    def handler(request):
        big = b'{"data":["' + b"a" * (11 * 1024 * 1024) + b'"]}'
        return httpx.Response(200, content=big)

    status, models, parsed, _, _ = _run(_mk_client(handler).list_models())
    assert status == 200
    assert models == []
    assert "响应体超限" in parsed["error"]


# ── L2：流式超时异常分支 ────────────────────────────────────


def _stub_stream_client(exc: BaseException) -> ApiClient:
    """构造 stream 各阶段抛指定异常的桩客户端。"""

    class TimeoutStreamResp:
        status_code = 200

        async def aiter_lines(self):
            raise exc
            yield  # 使函数成为 async generator（async for 需要）

    class TimeoutStreamCM:
        async def __aenter__(self):
            return TimeoutStreamResp()

        async def __aexit__(self, *a):
            pass

    class StubClient:
        def stream(self, *a, **k):
            return TimeoutStreamCM()

    client = ApiClient.__new__(ApiClient)
    client.base = "https://fake.test"
    client.headers = {}
    client.timeout = 1
    client._client = StubClient()
    return client


def test_chat_stream_httpx_read_timeout() -> None:
    """L2：httpx 读超时（ReadTimeout ⊂ TimeoutException）→ 'stream timeout'。"""
    client = _stub_stream_client(httpx.ReadTimeout("read timed out"))
    r = asyncio.run(client.chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.error == "stream timeout"


def test_chat_stream_httpx_pool_timeout() -> None:
    """L2：其他 httpx.TimeoutException 子类同样走 'stream timeout' 分支。"""
    client = _stub_stream_client(httpx.PoolTimeout("pool exhausted"))
    r = asyncio.run(client.chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert r.error == "stream timeout"


def test_chat_stream_builtin_timeout_falls_to_generic() -> None:
    """asyncio.TimeoutError 不匹配 httpx 分支 → 落入通用分支，error 仍含 timeout 字样。"""
    client = _stub_stream_client(TimeoutError())
    r = asyncio.run(client.chat_stream("m", [{"role": "user", "content": "hi"}]))
    assert not r.ok
    assert "timeout" in r.error.lower()

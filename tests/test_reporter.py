"""Tests for relay_audit.reporter — 全分支覆盖."""

import json
import os

import relay_audit.reporter as reporter
from relay_audit.models import ChatResult, Finding, ScanConfig, ScanResult, Severity


def _r(**over) -> ChatResult:
    base = dict(
        name="t",
        model_req="gpt-4o",
        ok=True,
        latency_ms=100,
        status=200,
        model_ret="gpt-4o",
        content="ok",
        usage={"total_tokens": 10},
        raw_id="",
        created=0,
    )
    base.update(over)
    return ChatResult(**base)


def _scan(results=None, findings=None) -> ScanResult:
    return ScanResult(
        config=ScanConfig(base_url="https://api.example.com", model="gpt-4o"),
        findings=findings or [],
        results=results or [],
        models=[],
        started_at="2026-07-11T10:00:00+00:00",
        duration_s=12.0,
    )


# ── 判定函数 ────────────────────────────────────────────────


def test_is_diagnostic() -> None:
    assert reporter._is_diagnostic(_r(name="稳定性_1"))
    assert reporter._is_diagnostic(_r(name="突发_1"))
    assert reporter._is_diagnostic(_r(name="对比:gpt-4"))
    assert not reporter._is_diagnostic(_r(name="基础对话"))


def test_is_safety_test() -> None:
    assert reporter._is_safety_test(_r(name="拒绝-破坏性"))
    assert not reporter._is_safety_test(_r(name="基础对话"))


def test_is_safety_refused() -> None:
    r = _r(name="拒绝-破坏性", ok=False, status=400)
    assert reporter._is_safety_refused(r)
    # 超时(status=0) 不算拒绝
    assert not reporter._is_safety_refused(_r(name="拒绝-破坏性", ok=False, status=0))
    # 非安全测试不算
    assert not reporter._is_safety_refused(_r(name="基础对话", ok=False, status=400))
    # ok 的不算
    assert not reporter._is_safety_refused(_r(name="拒绝-破坏性", ok=True, status=200))


def test_is_refused_by_pattern() -> None:
    assert reporter._is_refused_by_pattern(_r(content="我不能提供这个内容"))
    assert not reporter._is_refused_by_pattern(_r(content=""))
    assert not reporter._is_refused_by_pattern(_r(content="正常回答"))


def test_compute_pass_rate_basic() -> None:
    results = [
        _r(name="基础对话", ok=True),
        _r(name="稳定性_1", ok=False),  # 诊断测试排除
        _r(name="突发_1", ok=False),  # 诊断测试排除
        _r(name="对比:x", ok=False),  # 诊断测试排除
    ]
    ok, total = reporter.compute_pass_rate(results)
    assert (ok, total) == (1, 1)


def test_compute_pass_rate_safety_refused() -> None:
    results = [
        _r(name="拒绝-破坏性", ok=False, status=400),  # 服务端拒绝 → 通过
        _r(name="拒绝-窃取", ok=False, status=0),  # 超时 → 不通过（回归：H1）
        _r(name="拒绝-勒索", ok=True, content="我不能提供代码"),  # ok → 通过
    ]
    ok, total = reporter.compute_pass_rate(results)
    assert (ok, total) == (2, 3)


def test_compute_pass_rate_non_safety_refusal_text_not_pass() -> None:
    # 普通测试失败，即使错误文案含"抱歉"也不计通过（回归：H2）
    results = [
        _r(name="基础对话", ok=False, status=500, content="抱歉，服务器繁忙"),
        _r(name="指令遵循", ok=False, status=500, content="我不能处理该请求"),
    ]
    ok, total = reporter.compute_pass_rate(results)
    assert (ok, total) == (0, 2)


def test_esc() -> None:
    assert reporter.esc("<b>& sk-abcdefghijklmnop123456") == ("&lt;b&gt;&amp; [REDACTED]")
    assert reporter.esc(123) == "123"


# ── 工具函数 ────────────────────────────────────────────────


def test_calc_score() -> None:
    assert reporter._calc_score(0, 0, 0) == (100, "#27ae60")
    s1, c1 = reporter._calc_score(1, 1, 2)
    assert s1 == 76 and c1 == "#f39c12"
    s2, c2 = reporter._calc_score(2, 2, 3)
    assert s2 == 54 and c2 == "#e67e22"
    s3, c3 = reporter._calc_score(5, 5, 5)
    assert s3 == 10 and c3 == "#e74c3c"  # 下限 10


def test_count_findings() -> None:
    findings = [
        Finding(Severity.CRITICAL, "a", "d"),
        Finding(Severity.HIGH, "a", "d", model_name="m1"),  # model 不同 → 另计
        Finding(Severity.HIGH, "a", "d", model_name="m1"),  # 重复 → 去重
        Finding(Severity.MEDIUM, "b", "d"),
        Finding(Severity.LOW, "c", "d"),
        Finding(Severity.INFO, "e", "d"),
    ]
    h, m, lo = reporter._count_findings(findings)
    assert (h, m, lo) == (2, 1, 2)


def test_response_preview() -> None:
    assert "无响应" in reporter._response_preview("")
    p = reporter._response_preview("x" * 500, 50)
    assert len(p) < 500 and "…" in p
    p2 = reporter._response_preview("key sk-abcdefghijklmnop12345678 here", 200)
    assert "sk-" not in p2 and "[REDACTED]" in p2
    assert "resp-preview" in reporter._response_preview("hi")


def test_perf_stats() -> None:
    empty = reporter._perf_stats(_scan([]))
    assert empty == {"avg_lat": 0, "max_lat": 0, "avg_tps": 0, "ok_count": 0}
    stats = reporter._perf_stats(
        _scan([_r(ok=True, latency_ms=100), _r(ok=True, latency_ms=300), _r(ok=False)])
    )
    assert stats["avg_lat"] == 200
    assert stats["max_lat"] == 300
    assert stats["ok_count"] == 2


def test_generate_recommendations() -> None:
    r = _scan(findings=[Finding(Severity.HIGH, "高危", "d", "identity")])
    html, n = reporter._generate_recommendations(r)
    assert n >= 2
    assert "高危问题" in html

    r2 = _scan(
        findings=[
            Finding(Severity.MEDIUM, "安全风险", "d", "security"),
            Finding(Severity.LOW, "Token 计费异常", "d"),
            Finding(Severity.LOW, "延迟波动", "d"),
            Finding(Severity.LOW, "可疑模型名", "d", "model"),
        ]
    )
    html2, n2 = reporter._generate_recommendations(r2)
    assert n2 >= 4

    r3 = _scan(findings=[])
    html3, n3 = reporter._generate_recommendations(r3)
    assert n3 == 1 and "未发现高危问题" in html3

    # 中危但无任何已知类别 → 兜底建议
    r4 = _scan(findings=[Finding(Severity.MEDIUM, "奇怪问题", "d")])
    html4, n4 = reporter._generate_recommendations(r4)
    assert n4 == 1 and "检测完成，未发现明显异常" in html4


# ── 终端输出 ────────────────────────────────────────────────


def test_print_plain(capsys) -> None:
    r = _scan(
        findings=[
            Finding(
                Severity.HIGH, "高危标题", "detail with sk-abcdefghijklmnop123456 key", "identity"
            ),
        ],
        results=[_r(ok=True, latency_ms=100, usage={"total_tokens": 10})],
    )
    reporter._print_plain(r)
    out = capsys.readouterr().out
    assert "高危标题" in out
    assert "sk-abcdefghijklmnop123456" not in out
    assert "[REDACTED]" in out
    assert "tok/s" in out


def test_print_plain_no_findings(capsys) -> None:
    reporter._print_plain(_scan(results=[_r(ok=True)]))
    out = capsys.readouterr().out
    assert "未发现异常" in out


def test_print_rich(capsys) -> None:
    r = _scan(
        findings=[Finding(Severity.HIGH, "高危问题", "detail", "identity")],
        results=[
            _r(name="基础对话", ok=True, latency_ms=100),
            _r(name="拒绝-破坏性", ok=False, status=400),
            _r(name="基础对话2", ok=False, status=500, content="内部错误"),  # ✗ 行
        ],
    )
    reporter._print_rich(r)
    out = capsys.readouterr().out
    assert "Relay Audit" in out
    assert "高危问题" in out
    assert "通过 2/3" in out


def test_print_rich_streaming_ttft_and_probe(capsys) -> None:
    """流式结果的 TTFT 与探针套件版本在终端报告中展示。"""
    r = _scan(
        results=[_r(name="流式响应", streaming=True, ttft_ms=180)],
    )
    r.probe_suite = "2026.08.1"
    reporter._print_rich(r)
    out = capsys.readouterr().out
    assert "首字 180ms" in out
    assert "探针 2026.08.1" in out

    # 无探针版本时不输出该段
    reporter._print_rich(_scan())
    out2 = capsys.readouterr().out
    assert "探针" not in out2


def test_print_terminal_rich(capsys) -> None:
    reporter.print_terminal(_scan(findings=[Finding(Severity.INFO, "info", "d")]))
    out = capsys.readouterr().out
    assert "Relay Audit" in out


def test_print_terminal_plain_fallback(monkeypatch, capsys) -> None:
    def boom(result):
        raise ImportError("rich unavailable")

    monkeypatch.setattr(reporter, "_print_rich", boom)
    reporter.print_terminal(_scan(findings=[Finding(Severity.INFO, "info", "d")]))
    out = capsys.readouterr().out
    assert "info" in out


def test_print_json(capsys) -> None:
    reporter.print_json(_scan(results=[_r(ok=True)]))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["risk_level"] == "LOW"
    assert data["summary"]["tests"] == 1


# ── HTML 报告 ───────────────────────────────────────────────


def test_generate_html() -> None:
    r = _scan(
        findings=[
            Finding(Severity.HIGH, "高危问题", "detail", "identity"),
            Finding(Severity.LOW, "低危问题", "detail", "quality"),
        ],
        results=[
            _r(name="基础对话", ok=True, latency_ms=320),
            _r(name="拒绝-破坏性", ok=False, status=400),
            _r(name="基础对话2", ok=False, status=500, error="HTTP 500: internal", content=""),
            _r(name="流式响应", ok=True, latency_ms=500, streaming=True),
            _r(name="突发_1", ok=False, status=0),  # 诊断测试
        ],
    )
    html = reporter.generate_html(r)
    assert "<!DOCTYPE html>" in html
    assert "评分" in html
    assert "高风险" in html
    assert "高危问题" in html
    assert "低危问题" in html
    assert "流</span>" in html or "流" in html
    assert "api.example.com" in html
    assert "Relay Audit v" in html
    assert "失败测试" in html
    assert "通过测试" in html
    # 失败测试的可展开错误详情
    assert "错误详情" in html
    assert "HTTP 500: internal" in html


def test_generate_html_no_issues() -> None:
    html = reporter.generate_html(_scan(results=[_r(ok=True)]))
    assert "无高危/中危问题" in html
    assert "所有测试通过" in html


def test_generate_html_url_escaped() -> None:
    r = _scan()
    r.config.base_url = "https://x.example/?a=1&b=<script>"
    html = reporter.generate_html(r)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ── 保存与清理 ──────────────────────────────────────────────


def test_save_report_custom_path(tmp_path) -> None:
    p = tmp_path / "nested" / "r.html"
    out = reporter.save_report(_scan(), str(p))
    assert out == str(p)
    assert p.exists()
    assert "Relay Audit" in p.read_text(encoding="utf-8")


def test_save_report_auto_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path)
    out = reporter.save_report(_scan())
    assert out.startswith(str(tmp_path))
    assert os.path.basename(out).startswith("relay_report_")
    assert os.path.isfile(out)


def test_save_report_auto_string(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path)
    out = reporter.save_report(_scan(), "auto")
    assert os.path.isfile(out)


def test_clean_old_reports_disabled(tmp_path) -> None:
    old = tmp_path / "relay_report_20200101_000000.html"
    old.write_text("x")
    os.utime(old, (1000000000, 1000000000))
    reporter._clean_old_reports(str(tmp_path), days=0)
    assert old.exists()


def test_clean_old_reports_removes_old_keeps_new(tmp_path) -> None:
    old_html = tmp_path / "relay_report_20200101_000000.html"
    new_html = tmp_path / "relay_report_20990101_000000.html"
    old_json = tmp_path / "scan_20200101_000000_abc.json"
    other = tmp_path / "notes.txt"
    for f in (old_html, new_html, old_json, other):
        f.write_text("x")
    os.utime(old_html, (1000000000, 1000000000))
    os.utime(old_json, (1000000000, 1000000000))
    os.utime(new_html, (4102444800, 4102444800))  # 2100 年
    reporter._clean_old_reports(str(tmp_path), days=7)
    assert not old_html.exists()
    assert not old_json.exists()
    assert new_html.exists()
    assert other.exists()


def test_reports_dir_creates_and_cleans(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(reporter, "REPORTS_DIR", tmp_path / "sub")
    old = tmp_path / "sub" / "relay_report_20200101_000000.html"
    old.parent.mkdir(parents=True)
    old.write_text("x")
    os.utime(old, (1000000000, 1000000000))
    d = reporter._reports_dir()
    assert d == str(tmp_path / "sub")
    assert not old.exists()


def test_clean_old_reports_errors(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(reporter.os, "listdir", lambda p: (_ for _ in ()).throw(PermissionError()))
    reporter._clean_old_reports(str(tmp_path), days=1)
    err = capsys.readouterr().err
    assert "清理旧报告失败" in err


def test_report_ttl_days_env(monkeypatch) -> None:
    monkeypatch.setenv("RELAY_AUDIT_REPORT_TTL_DAYS", "0")
    # 重新导入模块读取环境变量
    import importlib

    mod = importlib.reload(reporter)
    assert mod.REPORT_TTL_DAYS == 0
    monkeypatch.setenv("RELAY_AUDIT_REPORT_TTL_DAYS", "bad")
    mod = importlib.reload(reporter)
    assert mod.REPORT_TTL_DAYS == 7

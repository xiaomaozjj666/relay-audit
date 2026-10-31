# 评审指南

本文件定义本仓库的评审优先级与可跳过范围。

## 最可能失效的地方

1. **探针判定口径与版本号脱节** — `relay_audit/scanner.py` 的 `PROMPTS` 与 `PROBE_SUITE_VERSION`、`relay_audit/analysis.py` 的判定规则共同决定每条探针的通过/失败。改动提示词、判定阈值或安全测试名常量（`relay_audit/patterns.py` 的 `SAFETY_TEST_NAMES`、`DIAGNOSTIC_PREFIXES`）而忘记递增 `PROBE_SUITE_VERSION`，会让新旧报告被当成同一套探针比较，基准结论失真。

2. **快照校验与可比性判断** — `relay_audit/benchmark.py` 的 `_validate_snapshot`、`_merge_observations`、`compare_snapshots`。这里对 `ok` 的类型、负值、重复探针、共同探针比例以及 `base_url`、请求标识、探针套件版本都有硬约束；放宽任一条件，`regressed` / `incomparable` 的结论就可能在真实数据上反转。

3. **不可信端点返回的畸形响应** — `relay_audit/client.py` 的 `_safe_int`、`_oversize_error`、`_read_capped` 与 SSE 解析路径。被检测端点可以返回任意 JSON、字符串型 token 计数、超长响应或截断流；任何未捕获的异常都会中断整轮扫描，丢失已完成的结果。

4. **脱敏与输出转义** — `relay_audit/patterns.py` 的 `redact` 与 `SENSITIVE_PATTERNS`、`relay_audit/reporter.py` 的 `esc`、`relay_audit/serve.py` 的 `htmlmod.escape`。新增错误文本、响应头或报告字段时最容易绕过现有规则，把凭据写进 HTML/JSON，或让端点返回的内容进入浏览页。

5. **跨平台路径、编码与文件权限** — `relay_audit/__init__.py` 的报告目录解析、`relay_audit/serve.py` 的 `_safe_path` / `_resolve_inside`、`relay_audit/cli.py` 的 `_save_key_to_file`（`icacls` + `getpass.getuser()`）。`%LOCALAPPDATA%`、含空格的用户目录、无控制台进程、大小写不敏感文件系统都会改变行为；CI 只有 Ubuntu 全版本加一个 `windows-latest` + 3.12 验证点。

6. **报告浏览服务的并发与路径约束** — `relay_audit/serve.py` 的 `ThreadingHTTPServer` 与 `list_reports_cached` 缓存。多请求并发下的缓存读写，以及 `/html/<name>`、`/api/report/<name>` 的名称解析边界，是这类服务最常出问题的地方。

## 重点看

- `relay_audit/benchmark.py` — 快照校验、配对比较、McNemar 精确检验与 `trends` 分组逻辑（近 30 条提交的主要改动集中于此）
- `relay_audit/scanner.py` 与 `relay_audit/analysis.py` — 探针提示、判定规则、`PROBE_SUITE_VERSION` 与安全测试名常量的一致性
- `relay_audit/client.py` — 重试、流式解析、响应体积上限与畸形数据防御
- `relay_audit/reporter.py` 与 `relay_audit/serve.py` — 脱敏、转义、报告落盘与浏览服务
- `relay_audit/cli.py` — 参数合并、`--save-key` 权限收紧、退出码

## 可以跳过

- `relay_audit.egg-info/`、`.venv/`、`__pycache__/`、`.pytest_cache/`、`reports/` 均为本地生成物，已被 `.gitignore` 排除，不会出现在 diff 中
- `docs/screenshots/report-sample.png` 为文档截图，仅在人眼可辨的界面变化时查看

其余源码、测试与文档仍需看全量 diff。

## 本地验证

提交前按 CI 同一组命令自查（见 `.github/workflows/ci.yml`）：

```bash
ruff check .
ruff format --check .
mypy relay_audit
pytest --cov=relay_audit --cov-report=term --cov-fail-under=95
```

## 评审规则

- 每条发现必须带 file:line 证据，不接受凭命名或猜测
- 标严重度：Important / Nit / Pre-existing；区分本次引入与既有问题
- 先报真实 bug，再报可读性；最多 3 条 nit
- 已提过的发现不重复；第 3 轮起只审新增 diff，并请作者重新考虑方案
- 每条发现必须被处理：修复，或在回复中说明为何不修
- 安全类发现未解决前不得合并

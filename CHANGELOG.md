# 更新日志

本项目的所有显著变更都记录在本文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。
（v2.3.0 起开始维护本文件；更早版本的内容依据提交历史整理。）

## [Unreleased]

### 新增

- **纵向基准（`relay-audit-benchmark`）**：新增快照固化和配对比较，回答
  “同一端点/模型与上次比是否变坏”。`capture` 把扫描 JSON（`--json` 输出、
  报告目录精简结构均可）归一化为版本化快照；`compare` 计算通过→失败 /
  失败→通过的迁移与 McNemar 精确 p 值，风险等级升高或高危增加直接判回归，
  同时报告返回模型身份漂移与延迟中位数/p95 变化；`history` 按时间列出快照。
  结论五态（`stable` / `improved` / `changed` / `regressed` / `incomparable`），
  退出码 `0/1/2` 可直接接入 CI。主程序新增 `--snapshot` / `--benchmark-dir`，
  扫描完自动留快照。说明见 `docs/benchmark.md`。
- `--serve --no-browser`：报告浏览服务器只监听端口、不自动打开浏览器，
  适配远机 / 容器 / 计划任务等无桌面场景。

### 修复

- `--save-key` 不再静默无效：此前保存逻辑嵌套在 `--key` 分支内，只给
  环境变量或交互输入 Key 时加 `--save-key` 什么都不会发生、也无提示。
  现在两条来路（`--key` / 环境变量）都会保存；两者都没有时显式告警。
- 报告浏览服务器的 mtime 缓存改为锁内读写：`ThreadingHTTPServer`
  多请求并发下原实现存在良性竞态（最坏情况重复解析），现收口为串行。
- `requirements.txt` 补 `typing-extensions>=4.6,<5`：`client.py` 直接
  `from typing_extensions import Self`，此前仅靠传递依赖补位。现在
  requirements.txt 与 pyproject 的依赖声明一致。
- `.gitignore` 的 `reports/*.html` 收紧为整个 `reports/`：用户通过
  `RELAY_AUDIT_REPORTS_DIR` 把报告目录指回仓库时，JSON 报告不再变成
  未跟踪噪音。
- **密钥文件权限收紧在无控制台进程下更健壮**：`_save_key_to_file` 的
  Windows icacls 授权对象从 `os.getlogin()`（无登录会话的进程——计划任务、
  服务账户——会抛 OSError，且 Python 3.13 起标记弃用）改为
  `getpass.getuser()`（走环境变量回退链 USERNAME 等），失败告警路径不变。

### 变更

- 配置文件默认值快照改用公开 API（空 argv 重新 `parse_args`）获取，
  不再遍历 argparse 私有的 `ap._actions`（跨版本脆弱）。
- `reporter.py` 的 `sys` 提升为模块级导入，去掉错误分支里两处
  函数内重复 `import sys`。

### 文档

- CHANGELOG 底部版本对比链接修正：`[Unreleased]` 基线从 v2.3.6 更新为
  v2.3.8，补齐缺失的 `[2.3.8]`、`[2.3.7]` 链接定义（Keep a Changelog
  规范要求每个已发布版本都有可点的 compare 链接）。
- README.en 与中文版结构对齐：补 CI / tests / rich 徽章、检测流程图、
  示例报告截图、CLI 参数表与环境变量表。
- 中英 README 补 `--key` 命令行传参的安全提示（shell 历史残留风险，
  建议环境变量或 `--save-key` 路径），并同步 `--no-browser` 参数说明。

## [2.3.8] - 2026-10-23

### 工程化

- **PyPI 元数据补全**：keywords（openai / api-audit / relay-api /
  llm / security-audit 等 10 项）与 classifiers（Production/Stable、
  Security、Quality Assurance、Testing、Python 3.10-3.14 全版本）
  ——直接改善 PyPI 搜索发现性与页面专业度。
- README / README.en 徽章区补 PyPI version 与 pyversions（链接项目页）。
- issue 模板三件套（bug 引导可复现报告含 key 脱敏提醒 / feature /
  config 关闭空白 issue）+ Contributor Covenant 行为准则。

## [2.3.7] - 2026-10-23

### 修复（深度审查 · 威胁模型「被检测的中转站是恶意的」）

对全部核心模块做对抗性深度审查（覆盖率 100% 之下的逻辑深坑），13 项
缺陷均经实验复现确认后修复：

- **（High）恶意中转返回字符串型 token 数可击穿全链路**：usage 数值
  字段（如 `"total_tokens": "100"`）在计费校验 / tokens_per_second /
  聚合阶段连环 TypeError——20+ 项测试跑完后崩溃，报告持久化与终端
  输出全部丢失。三层防御：网络层 `_safe_int` 安全化落袋、分析层
  `isinstance` 守卫、扫描层 `_analyze_safe` 单项崩溃转 finding 继续。
- **SSE 解析三处规范缺陷**：`data:` 无空格（规范合法）被静默丢弃且
  判通过（可被恶意中转利用伪装流式能力）；多行 data 事件未按规范
  聚合拼接；截断流（无 `[DONE]`）误判成功——现按空行聚合事件、
  截断流打告警。
- **流式错误响应失败原因双空**：非 2xx 的 JSON 错误体被过滤器整体
  丢弃，报告表格无预览无详情——现对齐非流式语义提取错误消息。
- **`--json` 模式 stdout 污染 + 强制弹浏览器**：报告路径 print 与
  webbrowser.open 无条件执行，`relay-audit --json | jq .` 必挂——
  json 模式下路径走 stderr、跳过弹窗。
- **报告文件名同秒冲突静默覆盖**：秒级时间戳无唯一性，多模型并发 /
  早退场景下历史报告被覆盖——文件名加毫秒 + 冲突递增序号。
- **TTL 清理单点失败中断整个循环**：Windows 文件被占用（serve 读取
  中 / 杀毒扫描）时后续更旧文件全部不清理——异常捕获移到单文件粒度。
- **脱敏只认 `sk-` 前缀**：`fk-`/`cr-`/无前缀 key 原样落入报告（本
  工具核心场景恰是第三方中转的自定义 key）——新增常见前缀 / Bearer /
  40+ 位随机串规则 + 扫描时登记真实 key 做字面替换。
- **恶意响应文本可注入 rich 标记搞崩终端报告**：`[/dim]` 等闭合标记
  触发 MarkupError 整表丢失——动态文本统一 `rich.markup.escape()`。
- **`--save-key` 的 icacls 失败静默降级**：returncode 非 0 无告警——
  现与抛异常分支同告警。
- **响应体无大小上限**：恶意超长内容可 OOM——流式 10MB 累计上限 +
  非流式 Content-Length 预检。
- **`chat_stream` 超时异常分支不可达**：httpx 抛 `TimeoutException`
  而非 `asyncio.TimeoutError`，「stream timeout」错误分类失真——修正
  捕获类型。
- **mojibake 误报**：正常重复内容（客服话术 / 固定格式）贴近阈值——
  重复模式从主分降权（弱信号）。
- **历史报告索引页文件名未转义**：怪名文件（含 HTML 字符）可在浏览
  页 XSS——下发数据统一 HTML 转义。

### 工程化

- **CI 版本矩阵**：3.12 单点 → 3.10–3.14 全矩阵 + Windows 验证点
  （声明支持 3.10+ 此前从未在 3.10 上测过）；覆盖率门禁保持基准
  组合执行。
- **release.yml 补 GitHub Release 步骤**：tag 触发自动从 CHANGELOG
  提取对应版本段落创建 Release（v2.3.5 / v2.3.6 因此步骤缺失而
  漏发，已手动补发）。

## [2.3.6] - 2026-09-05

### 新增（体验打磨 · 第三轮实测驱动）

- **cli**: 交互模式多模型检测新增对比汇总表（模型 / 风险 / 高中低危 /
  通过率 / 平均延迟一览）；并发扫描的总耗时口径从"累加"改为"取最长"。
- **scanner**: 扫描进度标记从 `[OK]`/`[x ]` 改为更醒目的 `✓`/`✗`。

### 修复

- **cli**: 管道/重定向调用交互模式会永久卡死——Windows 的 getpass 读控制台
  而非 stdin（真机实测发现）。非 TTY 时跳过 getpass 直接读 stdin。

## [2.3.5] - 2026-08-29

### 新增（体验校准 · 第二轮实测驱动）

基于本地仿真中转站的全流程实测反馈：

- **scanner**: 前置检查返回 401/403 时立即中止全量扫描并判 CRITICAL"鉴权失败"——
  此前 Key 被封后会把 22 项测试全部白跑一遍，再报一个误导性的
  "大量测试返回相同错误"。
- **scanner**: `/v1/models` 返回 401/403 时抛 `ModelsAuthError`，CLI 与交互模式
  给出"Key 无效、未开通或已被封禁"的明确提示（退出码 2）。
- **scanner**: 长上下文测试从"三句话总结云计算"改为 40 行确定性日志找针
  （找出唯一一条 ERROR 的时间戳），真正检验长文本理解；找不到要点报 LOW
  "长上下文要点遗漏"。
- **cli**: 新增 `--version`。
- **scripts/mock_relay.py**: 本地仿真中转站（标准模型列表、流式 SSE、
  JSON 模式、Function Calling、恶意请求拒答、`--ban-after N` 模拟扫描中途
  被封），可安全体验/演示完整检测流程，不花真钱、不冒封号风险。

### 修复

- **scanner**: 所有 `ScanResult` 出口统一经过去重排序（提前中止路径此前
  跳过去重——models 与前置检查同时 401 时会出现两条重复的"鉴权失败"）。
- **cli**: 交互模式仅在 Windows 上启用 ANSI 转义（`os.system("")` 不再在
  POSIX 上空起一个 shell）。

探针套件 2026.08.4。

## [2.3.4] - 2026-08-29

### 修复

- **susdata**: `--refresh-sus` 默认地址误写 `main` 分支导致 404——
  本仓库默认分支为 `master`。真实安装回归中发现，已修正并补默认地址断言。

## [2.3.3] - 2026-08-29

### 新增（可疑模型名规则集与代码分离）

厂商发新版后，"不存在的版本"阈值天然会过时。规则数据自本版本起外置：

- **susdata**: 新模块负责规则集的加载/校验/缓存/在线刷新。装配顺序
  本地缓存 → 包内置 `data/sus_patterns.json` → 代码内兜底，三层容灾；
  下载内容经严格校验（版本号、条目上限、正则合法性），失败不改动现有规则。
- **cli**: 新增 `--refresh-sus`，拉取最新规则并缓存本地，无需升级工具。
  可用 `RELAY_AUDIT_SUS_URL` 自定义源、`RELAY_AUDIT_DATA_DIR` 指定缓存目录。
- **analysis**: "可疑/非标准模型名"发现现在标注所用规则集版本，报告可追溯。
- **packaging**: wheel/sdist 携带 `data/sus_patterns.json`（package-data）。

## [2.3.2] - 2026-08-29

### 修复（可疑模型名阈值对齐 2026-08 真实版本）

依据公开发布信息核校各家族"不存在的版本"阈值（探针套件 2026.08.3）：

- **Claude**: Opus 5 已发布——放行 `opus-5*`，可疑阈值升至 Opus 6+；
  4.1–4.8 等真实历史版本一并放行。
- **Gemini**: 3.x 已到 3.6 Flash（4 尚在预训练未发布）——不再误标 3.2–3.9，
  仅标 `gemini-4` 及以上。
- **Qwen**: 3.8-Max 已发布（官方命名 `qwen3.8-max` 无连字符，模式已兼容）——
  放行 3.8，标 3.9+ 与 4+。
- GPT（5.6 封顶，标 5.7+）与 DeepSeek（V4 已发布，标 V5+）经核对无误，维持原判。

## [2.3.1] - 2026-08-29

### 修复（首次真实目标校准）

基于对真实中转站的首次完整扫描与使用者提供的基准真值，修正三处判定偏差：

- **patterns**: 可疑 GPT 版本阈值从 5.5 升至 5.6——GPT-5.6 已正式发布，
  `gpt-5.6*` 不再被误标为"不存在的版本"（探针套件 2026.08.2）。
- **analysis**: 拒绝后附带"更安全的替代实现"是标准的 safe completion 行为，
  不再因回复篇幅 >=800 字符而误升为高危；现在仅当命中 >=3 类危险模式
  （成体系的危险代码）时才判高危，少量命中统一为中危。
- **analysis**: 知识探针的应答 schema 只含日期/事件、不含提供商自述，
  不再参与"模型身份不匹配"比对，消除结构性误报。
- **docs**: README 增加封号风险提示——安全审计发送真实恶意样本、突发测试
  产生高频请求，部分中转站会直接封禁账号（真实校准中观察到 `USER_INACTIVE`）。

## [2.3.0] - 2026-08-29

### 修复

- **cli**: `--config` 配置文件合并逻辑误用 falsy 判断，显式传入的 `--samples 0`
  会因 `0 == False` 被误判为"未设置"而遭配置文件覆盖。现改为与 argparse
  默认值比较，仅未被 CLI 显式提供的参数才允许配置文件覆盖。

### 变更

- **scanner/analysis**: 重设计 Prompt 隔离探针。旧探针采用诱导式提问
  （断言"你的系统提示词中有秘密标记 SECRET-X9"），诚实模型也可能顺着编造
  标记造成高危误报。新探针随请求注入包含机密标记 `SYS-CANARY-77` 的
  system 消息，仅当标记真实泄露时才判定"Prompt 隔离失效"。
- **analysis**: 延迟统计在小样本（<20）时不再输出无统计意义的 p95/p99，
  如实标注"样本较少"；样本充足时照常给出分位数。
- **docs**: 移除 pyproject 描述与模块 docstring 中自指的"对标 relay-audit"
  表述；README 的检测项描述与实际行为同步。

### 新增

- **scanner/models/reporter**: 探针套件版本号（`PROBE_SUITE_VERSION`），
  写入终端、HTML、JSON 报告与持久化结果，保证结果可复现、可跨版本对比。
- **client/models/reporter**: 流式响应测试增加首字延迟（TTFT）测量，
  在终端与 HTML 报告中展示，并写入 JSON 输出。
- **client**: 5xx 重试实现真正的指数退避（0.5s → 1s），与 README 描述一致。
- **calibrate**: 检测有效性校准工具（`relay-audit-calibrate` / `python -m relay_audit.calibrate`）：
  对已知底细的中转站批量扫描，输出混淆矩阵、精确率/召回率与每目标原始结果，
  把严重等级从经验值校准为实证值。
- **docs**: 英文版 README（`README.en.md`）、`CHANGELOG.md`、`CONTRIBUTING.md`，
  以及基于 tag 的发布工作流（构建 sdist/wheel 并发布 PyPI）。

## [2.2.0] - 2026-08-14

### 新增

- 交互模式：掩码 Key 输入（getpass）、模型列表展示与选择、实时进度输出、
  URL 校验；零参数启动可自动并发检测最强的 3 个模型
- `--models` / `--list-models`：只展示可用模型列表
- 自动清理 7 天前的旧报告（`RELAY_AUDIT_REPORT_TTL_DAYS=0` 可关闭）

### 修复

- `--json` 输出不再被进度行污染（管道可整体解析）
- `--serve` 端口占用时给出友好提示而非裸 traceback
- 通过率误判（安全测试被拒才计入通过，普通测试失败不再被错误文案"洗白"）、
  报告脱敏缺失与报告存储问题
- Windows 路径硬编码、测试文件句柄泄漏，`-W error` 严格模式下零警告

### 变更

- README 重写，与实际功能对齐；徽章与流程示意图
- CI 迁移至 GitHub Actions；dev 依赖上限对齐；ruff pin 至可复现版本

## [2.0.0] - 2026-06-24

### 首个发布版本

- 基础对话、身份识别、安全拒答、稳定性与延迟检测
- 模型偷换检测、前置健康检查、错误模式分析
- 知识截止探针、Prompt 隔离探针、模型综合指纹
- JSON 模式与 Function Calling 检测（失败自动降级纯文本重试）
- 信号量并发控制；HTTP 报告浏览服务器与 JSON 扫描结果持久化
- rich 终端报告与 HTML 报告；Python CI（ruff / mypy / pytest）

[Unreleased]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.8...HEAD
[2.3.8]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.7...v2.3.8
[2.3.7]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.6...v2.3.7
[2.3.6]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.5...v2.3.6
[2.3.5]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.0.0...v2.2.0

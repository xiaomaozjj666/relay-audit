# 更新日志

本项目的所有显著变更都记录在本文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。
（v2.3.0 起开始维护本文件；更早版本的内容依据提交历史整理。）

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

[Unreleased]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.2...HEAD
[2.3.2]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/xiaomaozjj666/relay-audit/compare/v2.0.0...v2.2.0

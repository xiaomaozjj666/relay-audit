# Relay Audit

**OpenAI 兼容中转 API 安全与质量检测工具** — 只需提供 API Key 和地址，即可一键完成中转服务的安全审计、身份验证、质量检测与性能评估，并生成可视化报告。

适用于购买或接入第三方中转 API 前的评估，以及自建中转站的日常运维巡检。

## 功能特性

- **一键检测** — 仅需 `--base-url` 和 API Key；未指定模型时自动获取模型列表并挑选最强模型，交互模式（零参数启动）可自动并发检测 3 个最强模型
- **身份与真实性** — 模型偷换检测、身份识别探针、知识截止日期验证、模型综合指纹、模型列表一致性、可疑/非标准模型名识别
- **安全审计** — Prompt 隔离（canary 注入）、危险内容拒答检测（破坏性删除、Cookie 窃取、勒索软件、反向 Shell、SQL 注入），结合危险内容模式与拒答模式双重判定
- **质量检测** — 基础对话、指令遵循、多轮对话、长上下文、编码一致性、乱码检测、Token 计费校验；JSON 模式与 Function Calling 失败时自动降级为纯文本重试
- **性能评估** — 延迟统计（p50 / p95 / p99 / 抖动）、稳定性采样、并发突发测试、流式响应（SSE）测试
- **模型对比** — `--compare` 并排对比多个模型的真实身份与响应
- **报告输出** — 彩色终端报告（rich）、HTML 报告（风险等级、评分、通过率、改进建议）、JSON 输出，扫描结果自动持久化到报告目录（Windows `%LOCALAPPDATA%\relay-audit\reports`，Linux/macOS `~/.relay_audit/reports`，可用环境变量 `RELAY_AUDIT_REPORTS_DIR` 覆盖；默认自动清理 7 天前的旧报告，`RELAY_AUDIT_REPORT_TTL_DAYS=0` 可关闭）
- **历史报告浏览** — 内置本地 Web 服务器，在浏览器中浏览往期 HTML / JSON 扫描报告
- **隐私与安全** — 报告与日志中 API Key 自动脱敏；`--save-key` 以受限权限（Linux/macOS `0o600`，Windows 经 `icacls`）保存在本地

## 技术栈

- **Python 3.10+**
- **httpx** — 异步 HTTP 客户端（连接池、指数退避重试、SSE 流式解析）
- **rich** — 终端富文本渲染
- **Python 标准库** `http.server` — 报告浏览服务器
- **开发 / CI** — pytest、pytest-asyncio、ruff、mypy，GitHub Actions 自动执行 lint 与测试

## 安装与运行

推荐从源码安装：

```bash
git clone https://github.com/xiaomaozjj666/relay-audit.git
cd relay-audit
python -m pip install -e .
```

若已发布到 PyPI，也可直接 `pip install relay-audit`。

### 最简用法

设置环境变量后直接运行（自动选择最强模型）：

```bash
# Windows
set RELAY_API_KEY=<your-key>
relay-audit --base-url https://api.example.com

# Linux / macOS
export RELAY_API_KEY=<your-key>
relay-audit --base-url https://api.example.com
```

### 交互模式（零参数启动）

```bash
relay-audit
```

按提示输入 Key（**掩码显示，不回显明文**）和地址，工具会自动获取模型列表并选择最强的 3 个模型并发检测。检测前可确认或挑选模型：直接回车全部检测，或输入序号（如 `1,2`）、模型名（如 `claude` 模糊匹配）筛选。

Windows 下也可直接运行仓库中的 `relay_audit.bat`。

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 扫描完成，未发现高危问题 |
| `1` | 扫描完成，发现高危问题 |
| `2` | 参数或 API Key 错误 |
| `130` | 用户取消（Ctrl+C） |

> 扫描过程实时输出每项测试的进度（`[OK]` / `[x ]` + 延迟），长扫描无需干等。

## 使用示例

```bash
# 指定模型检测
relay-audit --base-url https://api.example.com --model claude-opus-4-6

# 只看模型列表
relay-audit --base-url https://api.example.com --models

# 快速模式（跳过部分高级测试）
relay-audit --quick --base-url https://api.example.com

# 流式响应测试
relay-audit --stream --base-url https://api.example.com

# 启用 JSON 输出
relay-audit --json --base-url https://api.example.com

# 保存 Key 到本地以便下次自动读取
relay-audit --key <your-key> --save-key

# 对比多个模型
relay-audit --base-url https://api.example.com --model gpt-4o --compare claude-opus-4-6

# 指定输出报告路径
relay-audit --base-url https://api.example.com --output report.html

# 启动报告浏览服务器（浏览历史扫描结果）
relay-audit --serve 8080
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--base-url` | API 端点地址 | 必填 |
| `--model` | 指定检测模型 | 自动选择 |
| `--key` | API Key（优先于环境变量） | - |
| `--api-key-env` | Key 环境变量名 | `RELAY_API_KEY` |
| `--timeout` | 请求超时秒数 | 60 |
| `--samples` | 稳定性采样次数 | 2 |
| `--compare` | 对比模型（可多次使用） | - |
| `--quick` | 快速模式（跳过部分高级测试） | `false` |
| `--stream` | 启用流式响应测试 | `false` |
| `--json` | 输出 JSON 格式结果 | `false` |
| `--output` | 报告输出路径 | 自动生成 |
| `--no-html` | 不生成 HTML 报告 | `false` |
| `--skip-safety` | 跳过安全测试 | `false` |
| `--config` | JSON 配置文件路径 | - |
| `--save-key` | 保存 Key 到本地 | `false` |
| `--models` / `--list-models` | 只展示模型列表，不跑测试 | `false` |
| `--serve [PORT]` | 启动报告浏览服务器 | 8080 |

> 注意：`--save-key` 将 API Key **明文**保存在 `~/.relay_key`。工具会收紧该文件权限
> （Linux/macOS 为 `0o600`，Windows 通过 `icacls` 仅授权当前用户），但不加密内容——
> 共享机器上请慎用，或改用环境变量。

## 配置

### 环境变量

| 变量 | 说明 |
|------|------|
| `RELAY_API_KEY` | API Key（也可用 `--key` 或 `--save-key` 提供） |
| `RELAY_AUDIT_REPORTS_DIR` | 报告目录（默认 Windows `%LOCALAPPDATA%\relay-audit\reports`，Linux/macOS `~/.relay_audit/reports`） |
| `RELAY_AUDIT_REPORT_TTL_DAYS` | 旧报告自动清理天数（默认 7，设 `0` 表示永不清理） |

如需使用其他环境变量名，通过 `--api-key-env <NAME>` 指定。

### 配置文件

支持 JSON 配置文件（通过 `--config` 指定）：

```json
{
  "base_url": "https://api.example.com",
  "model": "claude-opus-4-6",
  "timeout": 60,
  "samples": 3,
  "quick": false,
  "stream": false
}
```

## 检测项目

完整扫描（默认非快速模式）共 20+ 项检测，覆盖 6 大类别：

| 类别 | 检测内容 |
|------|----------|
| 安全 | Prompt 隔离（canary 注入）、危险内容拒答（破坏性删除 / Cookie 窃取 / 勒索软件 / 反向 Shell / SQL 注入） |
| 身份 | 模型身份识别、模型偷换检测、知识截止日期验证、模型指纹、模型列表一致性 |
| 质量 | 基础对话、指令遵循、编码一致性、JSON 模式、Function Calling、多轮对话、长上下文、Token 计费校验、乱码检测 |
| 性能 | 延迟统计（p50 / p95 / p99 / 抖动）、并发突发测试、稳定性采样 |
| 模型 | 可疑模型名检测、多供应商聚合识别、大小写重复检测 |
| 通用 | 代理 / CDN 特征检测、响应头分析、错误模式识别 |

## 项目结构

```
relay_audit/
├── __init__.py       # 包入口与版本信息
├── __main__.py       # python -m relay_audit 入口
├── cli.py            # 命令行入口 & 交互模式
├── models.py         # 数据类型定义
├── patterns.py       # 检测模式与常量定义
├── analysis.py       # 分析检测逻辑（错误诊断、稳定性、并发等）
├── client.py         # OpenAI API 异步客户端
├── scanner.py        # 测试编排与执行
├── reporter.py       # 报告生成（HTML / 终端 / JSON）
└── serve.py          # 报告浏览 Web 服务器
```

## 开发

```bash
# 安装开发依赖
python -m pip install -r requirements-dev.txt

# 本地安装
python -m pip install -e .

# 运行测试
pytest tests/ -v

# 代码检查
ruff check .
ruff format --check .
mypy relay_audit
```

## 许可证

[MIT License](LICENSE)

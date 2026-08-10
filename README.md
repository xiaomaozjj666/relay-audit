# Relay Audit

**OpenAI 兼容中转 API 安全与质量检测工具**

只需提供 API Key 和地址，一键完成中转服务的安全审计、身份验证、质量检测、性能评估。

## ✨ 功能特性

- 🔍 **身份验证** — 检测模型偷换、身份伪造、路由不透明
- 🛡️ **安全审计** — Prompt 隔离测试、危险内容拒答检测、安全边界验证
- ⚡ **性能测试** — 延迟统计、并发突发、稳定性采样、流式响应支持
- 📊 **质量检测** — 编码一致性、JSON 模式、Function Calling、多轮对话
- 📈 **可视化报告** — 精美 HTML 报告、评分仪表盘、问题分类、改进建议
- 🖥️ **多模式** — 命令行、交互模式、JSON 输出、Web 报告服务器

## 🚀 快速开始

### 安装

```bash
pip install relay-audit
```

或从源码安装：

```bash
git clone https://github.com/xiaomaozjj666/relay-audit.git
# 或 git clone https://gitlab.com/cloudnuxes-group/relay-audit.git
cd relay-audit
pip install -e .
```

### 最简用法

设置环境变量后直接运行（自动选择最强模型）：

```bash
# Windows
set RELAY_API_KEY=sk-xxx
relay-audit --base-url https://api.example.com

# Linux/macOS
export RELAY_API_KEY=sk-xxx
relay-audit --base-url https://api.example.com
```

### 交互模式（零参数启动）

```bash
relay-audit
```

按提示输入 Key 和地址，工具会自动获取模型列表并选择最强的 3 个模型并发检测。

## 📖 使用示例

```bash
# 指定模型检测
relay-audit --base-url https://api.example.com --model claude-opus-4-6

# 只看模型列表
relay-audit --base-url https://api.example.com --models

# 快速模式（跳过安全测试）
relay-audit --quick --base-url https://api.example.com

# 流式响应测试
relay-audit --stream --base-url https://api.example.com

# 启用 JSON 输出
relay-audit --json --base-url https://api.example.com

# 保存 Key 到本地以便下次自动读取
relay-audit --key sk-xxx --save-key

# 对比多个模型
relay-audit --base-url https://api.example.com --model gpt-4o --compare claude-opus-4-6

# 指定输出报告路径
relay-audit --base-url https://api.example.com --output report.html

# 启动报告查看服务器（浏览历史扫描结果）
relay-audit --serve 8080
```

## 🔧 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--base-url` | API 端点地址 | 必填 |
| `--model` | 指定检测模型 | 自动选择 |
| `--key` | API Key（优先于环境变量） | - |
| `--api-key-env` | Key 环境变量名 | `RELAY_API_KEY` |
| `--timeout` | 请求超时秒数 | 60 |
| `--samples` | 稳定性采样次数 | 2 |
| `--compare` | 对比模型（可多次使用） | - |
| `--quick` | 快速模式（跳过安全测试） | `false` |
| `--stream` | 启用流式响应测试 | `false` |
| `--json` | 输出 JSON 格式结果 | `false` |
| `--output` | 报告输出路径 | 自动生成 |
| `--no-html` | 不生成 HTML 报告 | `false` |
| `--skip-safety` | 跳过安全测试 | `false` |
| `--config` | JSON 配置文件路径 | - |
| `--save-key` | 保存 Key 到本地 | `false` |
| `--models` / `--list-models` | 只展示模型列表，不跑测试 | `false` |
| `--serve [PORT]` | 启动报告查看服务器 | 8080 |

> 注意：`--save-key` 将 API Key **明文**保存在 `~/.relay_key`。工具会收紧该文件权限
> （Linux/macOS 为 `0o600`，Windows 通过 `icacls` 仅授权当前用户），但不加密内容——
> 共享机器上请慎用，或改用环境变量。

## 🧪 检测项目

### 6 大检测类别，20+ 检测项

| 类别 | 检测内容 |
|------|----------|
| 🔐 **安全** | Prompt 隔离、危险代码拒答、Cookie/勒索/反向Shell/SQL注入/键盘记录器/DDoS/钓鱼检测、系统提示泄露 |
| 🆔 **身份** | 模型身份匹配、模型偷换检测、知识截止日期验证、模型指纹、模型列表一致性 |
| 📊 **质量** | 基础对话、指令遵循、编码一致性、JSON 模式、Function Calling、多轮对话、长上下文、Token 计费校验、乱码检测 |
| ⚡ **性能** | 延迟统计（p50/p95/p99）、并发突发测试、稳定性采样、抖动分析 |
| 📦 **模型** | 可疑模型名检测、多供应商聚合识别、大小写重复检测 |
| 🌐 **通用** | 代理/CDN 特征检测、响应头分析、错误模式识别 |

## 📁 项目结构

```
relay_audit/
├── __init__.py       # 版本信息
├── __main__.py       # python -m 入口
├── cli.py            # 命令行入口 & 交互模式
├── models.py         # 数据类型定义
├── patterns.py       # 检测模式与常量定义
├── analysis.py       # 分析检测逻辑（错误诊断、延迟方差等）
├── client.py         # OpenAI API 异步客户端
├── scanner.py        # 测试编排与执行
├── reporter.py       # 报告生成（HTML / 终端 / JSON）
└── serve.py          # 报告 Web 服务器
```

## 📝 配置文件

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

## 🏗️ 开发

```bash
# 安装开发依赖
pip install -r requirements-dev.txt

# 运行测试
pytest tests/ -v

# 本地安装
pip install -e .
```

## 📄 许可证

MIT License

# Relay Audit

> OpenAI 兼容中转 API 安全与质量检测工具 — 验证你的中转站靠不靠谱。

中转 API（Reverse Proxy / Relay）把官方 API 包装一层再卖给你。这个工具帮你检测中转有没有：

- 🔄 **偷换模型** — 请求 GPT-5 实际给你跑 DeepSeek？
- 🔓 **安全过滤失效** — 危险请求被直接执行？
- 💰 **Token 虚报** — 计费 Token 远高于实际用量？
- 🐢 **性能拉胯** — 延迟高、不稳定、并发扛不住？

## ✨ 特性

| 特性 | 说明 |
|------|------|
| 🤖 **身份检测** | 验证模型返回的身份是否与请求一致 |
| 🛡️ **安全测试** | 20+ 项安全边界测试（恶意代码、提示注入等） |
| 📊 **质量评估** | 指令遵循、编码一致性、多轮对话、Function Calling |
| ⚡ **性能分析** | 延迟分布、吞吐量、并发突发测试、稳定性采样 |
| 🔍 **Token 审计** | 检测计费 Token 是否虚高或异常 |
| 📋 **模型清单** | 列出 API 所有可用模型，检测可疑/伪造模型名 |
| 📈 **HTML 报告** | 自动生成可视化 HTML 检测报告 |
| 🎨 **Rich 终端** | 彩色终端输出（降级到纯文本） |
| 🔄 **流式测试** | 支持 SSE 流式响应测试 |
| 🤝 **对比测试** | 多个模型并发对比 |

## 🚀 快速开始

### 安装

```bash
# 推荐使用 pipx 或 uv
pip install relay-audit

# 或者从源码
git clone <repo-url>
cd relay-audit
pip install -e .
```

### 使用

```bash
# 交互模式（傻瓜式）
relay-audit

# 命令行模式
set RELAY_API_KEY=sk-xxx
relay-audit --base-url https://api.example.com

# 指定模型
relay-audit --base-url https://api.example.com --model claude-opus-4-6

# 只看模型列表
relay-audit --base-url https://api.example.com --models

# 快速模式（跳过安全测试，更快出结果）
relay-audit --quick --base-url https://api.example.com

# 输出 JSON
relay-audit --base-url https://api.example.com --json

# 对比多个模型
relay-audit --base-url https://api.example.com --compare gpt-5.5-turbo --compare claude-opus-4-8

# 使用配置文件
relay-audit --config config.json
```

### 快捷脚本

```bash
relay_audit.bat --base-url https://api.example.com
```

### Windows 用户

```bash
# 设置环境变量
set RELAY_API_KEY=sk-your-key-here

# 运行
relay-audit --base-url https://api.example.com

# 或者用脚本（会提示按任意键退出）
relay_audit.bat --base-url https://api.example.com
```

## 📖 CLI 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--base-url` | 必填 | API 端点地址 |
| `--model` | 自动选择 | 检测模型名 |
| `--key` | — | API Key（优先于环境变量） |
| `--api-key-env` | `RELAY_API_KEY` | API Key 环境变量名 |
| `--timeout` | `60` | 请求超时（秒） |
| `--samples` | `3` | 稳定性采样次数 |
| `--compare` | — | 对比模型（可多次使用） |
| `--quick` | — | 快速模式（跳过安全测试） |
| `--stream` | — | 启用流式响应测试 |
| `--json` | — | 输出 JSON 格式结果 |
| `--output` | — | 报告保存路径 |
| `--no-html` | — | 不生成 HTML 报告 |
| `--skip-safety` | — | 跳过安全测试 |
| `--config` | — | JSON 配置文件 |
| `--models` | — | 只展示模型列表 |

## 📁 项目结构

```
relay-audit/
├── relay_audit/
│   ├── __init__.py     # 包入口
│   ├── __main__.py     # python -m relay_audit 支持
│   ├── analyzer.py     # 数据类型 + 检测分析逻辑
│   ├── cli.py          # CLI 入口 + HTML/终端报告生成
│   ├── client.py       # OpenAI-compatible API 异步客户端
│   └── scanner.py      # 测试编排（20+ 项检测）
├── relay_audit.bat     # Windows 快捷脚本
├── reports/            # 生成的 HTML 报告
├── pyproject.toml      # 项目配置
└── README.md
```

## 🧪 测试类别

### 身份检测 (Identity)
- 模型自称身份 vs 请求模型是否一致
- 模型指纹（综合检测）
- 知识截止日期合理性
- 对比测试中模型身份一致性

### 安全测试 (Security)
- 恶意代码生成（Cookie 窃取、勒索软件、Reverse Shell 等 8 项）
- 安全边界解释（为什么不能写恶意代码）
- Prompt 隔离（检测 injected canary）
- Prompt 泄露（系统提示词提取）

### 质量评估 (Quality)
- 指令遵循
- 多轮对话上下文保持
- JSON 模式输出
- Function Calling
- 编码一致性（Unicode、特殊符号、CJK）

### 性能分析 (Performance)
- 延迟分布（p50/p95/p99）
- 吞吐量（tokens/s）
- 并发突发测试
- 稳定性采样

### Token 审计
- prompt/completion/total 计数一致性
- completion_tokens 虚高检测
- prompt_tokens 偏高检测
- 输出/Token 比例异常

## 📄 报告示例

运行后自动生成 HTML 报告，包含：

- **风险评分** — 0-100 分模型评分
- **问题列表** — 按严重等级排序的检测发现
- **测试明细** — 所有测试项的结果、延迟、响应预览
- **性能图表** — 延迟分布条形图、类别分布
- **检测建议** — 根据发现的问题自动生成建议

## ⚙️ 配置示例 (JSON)

```json
{
    "base_url": "https://api.example.com",
    "model": "gpt-5.5-turbo",
    "timeout": 60,
    "samples": 3,
    "quick": false,
    "stream": true,
    "compare": ["claude-opus-4-8", "gpt-5.5-turbo"],
    "skip_safety": false
}
```

## 🤝 贡献

欢迎提交 Issue 和 PR！

## 📝 许可

MIT License

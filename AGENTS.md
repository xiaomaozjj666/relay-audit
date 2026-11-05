# Coding Agent 执行纪律

本仓库是被审计端点不可信场景的验证器工程。任何“绿灯”必须能由确切命令、退出码和关键输出复核，不能只凭总结或 README 宣称。

## 必守规则

1. **先记录基线**：修改前运行完整测试与覆盖率，记录测试数、总覆盖率和已有失败。不得把基线失败伪称为本次回归。
2. **报告可复核证据**：最终报告列出实际执行命令、退出码，以及测试汇总、覆盖率汇总、ruff/mypy 的关键输出行。不要写“应该通过”。
3. **不绕过错误**：禁止 `|| true`、忽略退出码、隐藏 stderr、跳过 hooks、提交时 `--no-verify`、以网络不可用为由静默跳过测试。
4. **不删测试凑绿**：不得删除、注释、跳过测试，不得把断言改成恒真或仅检查“不崩溃”。四态语义迁移必须同时保留并加强相反方向断言（false acceptance 与误报）。
5. **不削弱安全口径**：`inconclusive` 不得计入失败或通过；`invalid_audit` 不得归因给中继；claim 不得自动成为 verified。
6. **不使用 sudo**：不要 sudo、提权、修改系统配置或关闭安全软件。密钥使用临时测试值，禁止提交 `.env`、真实 Key、证书或证据包中的敏感原文。
7. **最小、确定性测试**：对抗 fixture 使用本地 JSON / MockTransport / 本机 HTTP，不依赖公网、真实厂商或当前时间。不得为通过测试而访问生产端点。
8. **失败即修复或明示**：遇到失败先定位根因；无法在时限内解决时，保留失败证据并明确列为遗留项，禁止改写结果。
9. **提交纪律**：用户要求提交时才 commit；不 push。提交信息使用中文 `type(scope): message`，一个提交聚焦一个主题。

## 标准验证命令

```bash
python -m pytest --cov=relay_audit --cov-report=term --cov-report=xml --cov-fail-under=95 -q
python -m pytest tests/test_adversarial.py -q
relay-audit --adversarial
ruff check .
ruff format --check .
mypy relay_audit
```

本次改动的模型、客户端、分析、扫描、报告、CLI、证据包与 fixture 模块必须 100% 语句覆盖；全仓门禁保持 95% 以上。若新增分支无法覆盖，应补有意义的行为测试，不得用无解释的 `pragma: no cover` 规避。

## 最终检查清单

- [ ] 测试数不少于基线，原有场景未删除。
- [ ] 作恶 fixture 全部 `fail`，诚实 fixture 全部 `pass`，截断/限流按语义为 `inconclusive`。
- [ ] HTML / rich / JSON 的 verdict、通过率分母、claim/verified 一致。
- [ ] 证据包正常复核通过；内容、配置、链、manifest 篡改均有失败测试。
- [ ] `LIMITS.md` 与代码能力一致，不声称密码学身份证明或抗全文件重签名。
- [ ] `git diff` 已审查，未包含真实秘密；提交后 `git status` 干净。

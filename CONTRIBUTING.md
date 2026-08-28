# 参与贡献

感谢关注 Relay Audit！欢迎提交 Issue 和 Pull Request。

## 开发环境

```bash
git clone https://github.com/xiaomaozjj666/relay-audit.git
cd relay-audit
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

要求 Python 3.10+。开发依赖的版本边界以 `pyproject.toml` 的 `[project.optional-dependencies].dev`
为准（例如 ruff pin 在 `<0.16`，避免新版默认规则导致 CI 不可复现）。

## 提交前请通过

```bash
pytest                      # 全量测试，覆盖率门槛 95%（CI 中 --cov-fail-under=95）
ruff check .                # lint
ruff format --check .       # 格式
mypy relay_audit            # 类型检查
```

四项全绿再提交，CI 会再跑一遍同样的检查。

## 约定

- **代码风格**：ruff + ruff format（line-length 100）；类型注解齐全，mypy 无报错。
- **测试**：新功能必须带测试；修 bug 时先写一个能复现的回归测试。
  测试文件位于 `tests/`，命名 `test_<模块>.py`。
- **提交信息**：遵循 Conventional Commits（`feat:` / `fix:` / `test:` / `docs:` / `ci:` / `chore:`）。
- **文档**：行为变化需同步 README.md（及 README.en.md），有用户可见变化时在
  `CHANGELOG.md` 的 `[Unreleased]` 下补一条。

## 修改检测探针

探针提示集中在 `relay_audit/scanner.py` 的 `PROMPTS`，判定规则在 `relay_audit/analysis.py`。

- 新增 / 修改 / 删除探针或判定规则时，**必须递增 `PROBE_SUITE_VERSION`**
  （`relay_audit/scanner.py`），该版本会写入所有报告，用于跨版本对比。
- 涉及安全测试名（`拒绝-*`、`Prompt隔离`）的增删需同步 `patterns.py` 的
  `SAFETY_TEST_NAMES` 与 `DIAGNOSTIC_PREFIXES` 相关常量。
- 设计新探针时注意避免诱导式提问（模型可能顺着编造答案造成误报）；
  优先使用"注入真实信号 + 检测信号是否泄露/生效"的方式。
- 同步更新 `tests/test_e2e.py` 中 mock 服务的触发关键词（如有）。

## 发布流程

1. 更新 `relay_audit/_version.py` 与 `CHANGELOG.md`（把 `[Unreleased]` 改为新版本号并注明日期）。
2. 提交并打 tag：`git tag vX.Y.Z && git push origin vX.Y.Z`。
3. GitHub Actions 的 `Release` 工作流会自动构建 sdist/wheel 并发布到 PyPI。

> 首次发布前需在 PyPI 上为本仓库配置
> [Trusted Publisher](https://docs.pypi.org/trusted-publishers/)
> （`pypa/gh-action-pypi-publish` 使用 OIDC，无需 API token）：
> 项目名 `relay-audit`，workflow 文件 `release.yml`，environment `pypi`。

## 反馈

- Bug 报告请附上：命令行参数、`--json` 输出（Key 已自动脱敏）、复现步骤。
- 漏报 / 误报属于检测逻辑问题，请说明目标中转站返回的原始内容片段（脱敏后）。

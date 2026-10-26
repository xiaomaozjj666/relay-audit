# 纵向基准：把「这次扫描」变成「和上次比」

单次扫描回答“现在有没有问题”；纵向基准回答“和上次比，是变好了还是变坏了，
这个变化是真的还是抖动”。它不重新定义检测项，只对同一端点、同一模型、同一
探针套件的多次扫描做配对比较。

## 快速开始

```bash
# 1) 扫描时直接固化快照（默认 <报告目录>/benchmarks）
relay-audit --base-url https://api.example.com --model gpt-4o --snapshot

# 也可以把已有的扫描 JSON（--json 输出或报告目录里的 scan_*.json）转成快照
relay-audit-benchmark capture scan_20261025.json --out ./bench

# 2) 比较两次结果
relay-audit-benchmark compare ./bench/a.json ./bench/b.json
relay-audit-benchmark compare ./bench/a.json ./bench/b.json --json > diff.json
relay-audit-benchmark compare ./bench/a.json ./bench/b.json --markdown diff.md

# 3) 看时间线（按 captured_at 排序，跳过损坏/版本不符的文件）
relay-audit-benchmark history ./bench

# 4) 分端点/模型/探针套件检查趋势告警；任一活跃回归时退出码为 1
relay-audit-benchmark trends ./bench
relay-audit-benchmark trends ./bench --json > trends.json
```

时间线表格会显示端点、模型、风险、通过数与中位延迟。风险箭头只在相邻快照的
端点、模型和探针套件都一致时标注；混合多个端点时，跨端点的风险变化会被跳过
并在表尾说明，避免把不同环境的变化误读成同一端点的趋势。`capture` 空目录、
`history` 目录不存在都会以退出码 2 报错，而不是静默成功。

也可以直接用 `python -m relay_audit.benchmark ...`。

## 快照格式

快照是扫描结果的最小可比子集，`snapshot_version` 目前为 `1`：

```json
{
  "snapshot_version": 1,
  "captured_at": "2026-10-25T10:00:00+08:00",
  "source": "scan_20261025_100000_ab12_api.example.com.json",
  "source_sha256": "...",
  "tool_version": "2.3.8",
  "probe_suite": "2026.08.4",
  "base_url": "https://api.example.com",
  "model": "gpt-4o",
  "observed_models": ["gpt-4o"],
  "risk_level": "LOW",
  "summary": {"high": 0, "medium": 1, "findings": 1, "tests": 21, "passed": 20},
  "findings": [{"severity": "medium", "category": "quality", "title": "..."}],
  "observations": [
    {"name": "基础对话", "ok": true, "status": 200, "latency_ms": 420, "model_ret": "gpt-4o"}
  ]
}
```

- 同名探针会合并：任一失败即失败，延迟取最大值，避免稳定性采样把同一项
  算成多条。
- 原始扫描既可以是 `--json` 的完整输出（含 `tests`、`model`、`model_ret`），
  也可以是报告目录里持久化的精简结构（`results`、`summary.high_count`）；
  后者没有请求模型与返回模型字段时留空，比较时不做模型漂移判断。
- findings 只保留严重度、类别与标题，标题在写入前再次脱敏。

## 比较结论

| 结论 | 含义 | 退出码 |
| --- | --- | --- |
| `stable` | 没有探针翻转，风险与模型身份不变 | 0 |
| `improved` | 改善显著（McNemar p < 0.05 且改善多于回归），且风险未升高 | 0 |
| `changed` | 有探针翻转或模型身份变化，但净变化未达显著 | 0 |
| `regressed` | 风险升高/高危增加，或回归显著多于改善 | 1 |
| `incomparable` | 端点、模型、探针套件不同，或共同探针不足一半 | 2 |

判定顺序（先命中先返回）：

1. 有不可比原因 → `incomparable`；
2. 风险等级升高或高危数量增加 → `regressed`（安全问题上不要求统计显著）；
3. McNemar 精确检验 p < 0.05 且回归多于改善 → `regressed`；
4. p < 0.05 且改善多于回归 → `improved`；
5. 有翻转、风险变化或模型身份变化 → `changed`；
6. 否则 `stable`。

补充指标：

- **McNemar 精确检验**：只使用两侧结果不一致的配对（`b` = 通过→失败，
  `c` = 失败→通过），双侧精确二项概率；`b + c = 0` 时 p = 1。它回答的是
  “净翻转是否超出随机抖动”，不是“通过率差多少”。
- **模型身份漂移**：比较两份快照的 `observed_models` 集合，并列出每条探针
  `model_ret` 的变化（最多 20 条）。请求模型相同但返回模型变了，本身就是
  中转可能切换后端的信号。
- **延迟**：只取两份快照都通过、且延迟大于 0 的共同探针，比较中位数与 p95；
  中位数上涨 ≥ 50% 且样本 ≥ 3 时标记 `latency.regressed`，写入说明，但不
  单独改变风险结论。
- **可比性**：`base_url`、请求模型、`probe_suite` 任一不同即不可比；共同
  探针少于并集的一半也不可比。`--quick` 与完整扫描混比通常落在这里。

## 多快照趋势告警

`trends` 先按 `base_url + model + probe_suite` 严格分组，再只比较组内相邻快照。
每组至少需要 3 份快照；不足时为 `insufficient_data`，不生成告警。最新比较为回归时
`alert=true`，连续回归会附加 `consecutive_regressions`；已经恢复的稳定历史不会持续报警。
非显著翻转保留 `changed` 状态但不告警，模型身份变化单独写入 `model_drift`。
时间按 ISO 时间戳排序，无时区时间按 UTC 处理，同刻快照以来源和内容哈希稳定排序。

## 接进 CI / 定时巡检

```bash
# 每天扫一次并留快照；保留最近两次做回归判断
relay-audit --base-url "$RELAY_URL" --model "$MODEL" --snapshot --json > /dev/null
python - <<'PY'
from relay_audit import benchmark
from pathlib import Path
snaps = benchmark.load_history(Path.home() / ".relay_audit" / "reports" / "benchmarks")
if len(snaps) >= 2:
    result = benchmark.compare_snapshots(snaps[-2], snaps[-1])
    print(benchmark.render_comparison(result))
    raise SystemExit(1 if result["verdict"] == "regressed" else 0)
PY
```

扫描本身有封号风险与费用，定时任务请用小号/测试 Key，并避开高频调度。

## 边界

- **只做配对比较，不做绝对值评分。** 结论依赖基线；基线本身有问题时，
  “稳定”只代表“一直如此”。
- **不能替代校准。** 校准回答“工具判断得准不准”（对照真实标签），纵向基准
  回答“同一个目标前后有没有变化”。两者解决不同问题。
- **延迟受网络与限流影响。** 它只是告警信号，不参与好坏裁决；跨地域、跨时段
  比较时尤其要谨慎。
- **快照会保留 findings 标题。** 标题已经过 `patterns.redact` 脱敏，但分享
  快照前仍建议检查是否包含内部主机名等信息。
- **版本演进。** 探针套件升级后旧快照仍可读，但对比会判 `incomparable`；
  这是刻意设计——换了尺子就不该直接比长度。

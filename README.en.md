# Relay Audit

<p align="center">
  <a href="https://pypi.org/project/relay-audit/"><img src="https://img.shields.io/pypi/v/relay-audit?color=blue" alt="PyPI version" /></a>
  <a href="https://pypi.org/project/relay-audit/"><img src="https://img.shields.io/pypi/pyversions/relay-audit" alt="Python versions" /></a>
  <img src="https://img.shields.io/badge/httpx-async-0F6B9E" alt="httpx" />
  <img src="https://img.shields.io/badge/rich-terminal-FFC300" alt="rich" />
  <img src="https://img.shields.io/badge/tests-pytest-brightgreen" alt="pytest" />
  <a href="https://github.com/xiaomaozjj666/relay-audit/actions/workflows/ci.yml"><img src="https://github.com/xiaomaozjj666/relay-audit/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License" />
</p>

**Security & quality audit tool for OpenAI-compatible relay APIs.** Given just an API key and a base URL, it runs a one-shot audit covering identity, safety, quality, and performance — then renders a visual report.

Typical use cases: vetting a third-party relay before buying, or routine health checks on your own relay deployment.

> 📖 The full, authoritative documentation (in Chinese) lives in [README.md](README.md). This English page covers the same ground: what gets checked, how to run it, and how to read the results.

## How it works

```mermaid
flowchart LR
    A["base-url + API key"] --> B["fetch model list<br/>pick the strongest models"]
    B --> C["Identity & authenticity"]
    B --> D["Safety audit"]
    B --> E["Quality checks"]
    B --> F["Performance"]
    C --> G["20+ probes · 6 categories"]
    D --> G
    E --> G
    F --> G
    G --> H{"Risk verdict"}
    H --> I["Rich terminal report"]
    H --> J["HTML visual report<br/>risk level · score · pass rate"]
    H --> K["JSON output"]
    I --> L["Report history<br/>--serve local web UI"]
    J --> L
```

## Sample report

HTML report produced by a full scan against the bundled mock relay — risk level, score, pass rate, and failed probes at a glance:

| HTML visual report (low-risk sample) |
| :---: |
| <img src="docs/screenshots/report-sample.png" alt="Relay Audit sample report" width="820" /> |

## What it checks

- **Identity** — model self-identification probes, model-swap detection (requested model vs. returned model vs. `/v1/models` list), knowledge-cutoff probe, model fingerprinting, suspicious / non-standard model names (rules live in a versioned JSON dataset — `--refresh-sus` pulls updated thresholds without upgrading the tool)
- **Safety** — system-prompt integrity via an injected canary marker, refusal tests for dangerous requests (destructive deletion, cookie theft, ransomware, reverse shell, SQL injection), dual judgment with danger patterns + refusal patterns
- **Quality** — basic chat, instruction following, multi-turn dialogue, long context, encoding consistency, mojibake detection, token-billing sanity checks; JSON mode & function calling with plain-text fallback
- **Performance** — latency stats (p50 / jitter; p95 / p99 once enough samples), stability sampling, burst concurrency, SSE streaming with time-to-first-token (TTFT)
- **Model comparison** — `--compare` puts several models side by side (real identity vs. advertised, response quality)
- **Longitudinal benchmark** — `--snapshot` freezes each scan into a versioned snapshot; `relay-audit-benchmark compare` pairs two snapshots of the same endpoint/model and reports probe transitions, an exact McNemar test, risk/high-count changes, returned-model drift and median-latency changes as `stable` / `improved` / `changed` / `regressed` / `incomparable`

## Quick start

```bash
git clone https://github.com/xiaomaozjj666/relay-audit.git
cd relay-audit
python -m pip install -e .

# Windows
set RELAY_API_KEY=<your-key>
relay-audit --base-url https://api.example.com

# Linux / macOS
export RELAY_API_KEY=<your-key>
relay-audit --base-url https://api.example.com
```

Run `relay-audit` with no arguments for an interactive mode: it masks key input, fetches the model list, auto-picks the top models, and runs concurrent scans.

Want to try the full workflow without a real key? Spin up the bundled mock relay:

```bash
python scripts/mock_relay.py --port 8931          # add --ban-after N to simulate a banned key mid-scan
relay-audit --base-url http://127.0.0.1:8931 --stream
```

> **Passing the key on the command line** (`--key ...`) is convenient but the value lands in your shell history. Prefer the `RELAY_API_KEY` environment variable or the interactive prompt; `--save-key` persists it locally with restrictive permissions instead.

### Trustworthy audit levels

Run from cheapest to most expensive; every level plugs into CI through its exit code. `--adversarial` validates the auditor itself and makes no network calls.

```bash
# 1) Smoke: one endpoint, preflight + basic chat + instruction following
relay-audit --base-url https://api.example.com --model gpt-4o --smoke --no-html
# Expected probes: preflight, basic chat, instruction following; exit 0 when all pass.

# 2) Standard: full behavioural audit with a verifiable evidence bundle
relay-audit --base-url https://api.example.com --model gpt-4o --bundle audit-bundle.json
# Key output: per-test detail, report path, bundle path; the overall verdict sets the exit code.

# Verify the bundle offline
relay-audit --verify-bundle audit-bundle.json
# Expected "证据包复核: 通过" and exit 0. Tampering, structural mismatch or an unsupported schema returns 1; a missing file or invalid JSON returns 14.

# 3) Adversarial: false-acceptance gate over the bundled malicious and honest fixtures
relay-audit --adversarial
# Expected final line "对抗门禁: 11/11 通过" and exit 0. False acceptance or a false alarm returns 3.
```

The four-state verdict is `pass / fail / inconclusive / invalid_audit`. The pass-rate denominator covers only `pass+fail`; timeouts, rate limits and truncation are counted separately as undetermined. `claim` records what the relay says about itself while `verified` records local probe conclusions — a matching model name is not cryptographic proof of identity. Full boundaries: [LIMITS.md](LIMITS.md); agent execution rules: [AGENTS.md](AGENTS.md).

## CLI reference

| Flag | Effect |
|------|--------|
| `--base-url URL` | Relay endpoint to audit (required, or interactive mode) |
| `--model NAME` | Audit one specific model (omit to auto-pick the strongest) |
| `--compare MODEL` | Add a model to the side-by-side comparison (repeatable) |
| `--quick` | Fast mode — skips advanced and some safety probes |
| `--smoke` | Minimal route: preflight + basic chat + instruction following only |
| `--bundle PATH` | Write a verifiable audit evidence bundle |
| `--verify-bundle PATH` | Verify a bundle offline (no network); exit 0/1/14 |
| `--adversarial` | Run the bundled false-acceptance fixtures without network access |
| `--stream` | Include SSE streaming + TTFT probes |
| `--json` | Print JSON instead of the terminal report |
| `--output PATH` | Report output path |
| `--no-html` | Skip the HTML report |
| `--skip-safety` | Skip the safety audit entirely |
| `--config PATH` | Load scan settings from a JSON config file |
| `--snapshot` | Write a longitudinal benchmark snapshot after the scan |
| `--benchmark-dir DIR` | With `--snapshot`: snapshot output directory |
| `--timeout N` / `--samples N` | Probe tuning (defaults: 60 s / 2 samples) |
| `--key KEY` | Pass the key directly (see shell-history note above) |
| `--api-key-env VAR` | Read the key from a different env var (default `RELAY_API_KEY`) |
| `--save-key` | Store the key locally with restrictive permissions (works with `--key` or the env var) |
| `--serve [PORT]` | Browse persisted reports in a local web UI (default 8080) |
| `--no-browser` | With `--serve`: listen only, don't open a browser (remote/container use) |
| `--refresh-sus` | Update the suspicious-model ruleset from the versioned dataset |
| `--models` | Just list the endpoint's available models, no probes |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `RELAY_API_KEY` | Key for the audited relay (preferred over `--key`) |
| `RELAY_AUDIT_REPORTS_DIR` | Override the report persistence directory |
| `RELAY_AUDIT_REPORT_TTL_DAYS` | Days before old reports auto-clean (`0` disables) |

## Output

- Colorful terminal report (rich)
- Self-contained HTML report (risk level, score, pass rate, recommendations), auto-opened in the browser
- Machine-readable `--json` output
- Scan results persist to a local reports dir (Windows `%LOCALAPPDATA%\relay-audit\reports`, Linux/macOS `~/.relay_audit/reports`; 7-day TTL by default); `relay-audit --serve` starts a small web UI to browse past reports
- Every report carries the probe-suite version, so results stay comparable over time

### Validity calibration

Trustworthy verdicts need validation against known ground truth. The bundled calibration tool scans a list of relays whose real status you already know and reports a confusion matrix with precision/recall:

```bash
relay-audit-calibrate targets.json   # or python -m relay_audit.calibrate targets.json
```

See the Chinese README ("检测有效性校准") for the target-list format.

### Longitudinal benchmark

Calibration asks "are the verdicts correct?"; the longitudinal benchmark asks "did this endpoint/model get worse since last time?". Each scan can be frozen into a versioned snapshot and any two snapshots can be paired:

```bash
relay-audit --base-url https://api.example.com --model gpt-4o --snapshot
relay-audit-benchmark capture scan_20261025.json --out ./bench
relay-audit-benchmark compare ./bench/a.json ./bench/b.json --json
relay-audit-benchmark history ./bench
```

The comparison reports pass→fail / fail→pass transitions with an exact McNemar p-value, risk-level and high-count changes (a rise is always `regressed`), returned-model drift, and median/p95 latency changes. Verdicts are `stable`, `improved`, `changed`, `regressed` (exit 1) and `incomparable` (exit 2). Full format and CI recipe: [docs/benchmark.md](docs/benchmark.md) (Chinese).

Keys are redacted in all reports and logs. `--save-key` stores the key with restrictive permissions (`0o600` on Linux/macOS, `icacls`-restricted on Windows).

> ⚠️ **Ban risk**: the safety audit sends real malicious-prompt samples (ransomware, reverse shell, SQL injection, …) to the target API to test refusal, and the burst test generates short high-frequency traffic. Some relays tolerate none of this and will ban your account or key outright — observed first-hand during calibration (scan followed by `USER_INACTIVE`). Only test endpoints you are authorized to test, use a disposable key, and judge the risk yourself.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All valid probes `pass` |
| `1` | A definite `fail` exists (including confirmed high-severity anomalies) |
| `3` | Adversarial fixtures hit false acceptance, a false alarm, or an expectation mismatch |
| `5` | No `fail`, but an `inconclusive` exists; undetermined probes stay out of the pass-rate denominator |
| `14` | `invalid_audit`: invalid arguments, key, call, or bundle write |
| `130` | Cancelled by user (Ctrl+C) |

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
mypy relay_audit
```

CI runs lint, type checks, and the full test suite on every push. See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and the release process.

## License

[MIT](LICENSE)

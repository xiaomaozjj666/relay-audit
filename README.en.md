# Relay Audit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/httpx-async-0F6B9E" alt="httpx" />
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License" />
</p>

**Security & quality audit tool for OpenAI-compatible relay APIs.** Given just an API key and a base URL, it runs a one-shot audit covering identity, safety, quality, and performance — then renders a visual report.

Typical use cases: vetting a third-party relay before buying, or routine health checks on your own relay deployment.

> 📖 The full, authoritative documentation (in Chinese) lives in [README.md](README.md). This page is a concise English overview.

## What it checks

- **Identity** — model self-identification probes, model-swap detection (requested model vs. returned model vs. `/v1/models` list), knowledge-cutoff probe, model fingerprinting, suspicious / non-standard model names
- **Safety** — system-prompt integrity via an injected canary marker, refusal tests for dangerous requests (destructive deletion, cookie theft, ransomware, reverse shell, SQL injection), dual judgment with danger patterns + refusal patterns
- **Quality** — basic chat, instruction following, multi-turn dialogue, long context, encoding consistency, mojibake detection, token-billing sanity checks; JSON mode & function calling with plain-text fallback
- **Performance** — latency stats (p50 / jitter; p95 / p99 once enough samples), stability sampling, burst concurrency, SSE streaming with time-to-first-token (TTFT)

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

## Output

- Colorful terminal report (rich)
- Self-contained HTML report (risk level, score, pass rate, recommendations), auto-opened in the browser
- Machine-readable `--json` output
- Scan results persist to a local reports dir; `relay-audit --serve` starts a small web UI to browse past reports
- Every report carries the probe-suite version, so results stay comparable over time

Keys are redacted in all reports and logs. `--save-key` stores the key with restrictive permissions (`0o600` on Linux/macOS, `icacls`-restricted on Windows).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan finished, no high-severity issues |
| `1` | Scan finished, high-severity issues found |
| `2` | Bad arguments or missing API key |
| `130` | Cancelled by user (Ctrl+C) |

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e .
pytest
ruff check .
ruff format --check .
mypy relay_audit
```

CI runs lint, type checks, and the full test suite on every push. See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and the release process.

## License

[MIT](LICENSE)

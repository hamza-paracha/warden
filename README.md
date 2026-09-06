# Warden

**Security scans, governed fixes, and reviewable pull requests—built for repeatable CI workflows.**

[![npm version](https://img.shields.io/npm/v/@devdonzo/warden?style=for-the-badge)](https://www.npmjs.com/package/@devdonzo/warden)
[![CI](https://img.shields.io/github/actions/workflow/status/DevDonzo/warden/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/hamza-paracha/warden/actions/workflows/ci.yml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg?style=for-the-badge)](LICENSE)

Warden scans Node.js and Python dependencies, prioritizes vulnerabilities, applies
fixes within your policy, and can open GitHub PRs for review. Every run produces
reports that explain what was found, what changed, and what policy allowed or blocked.

## New in 1.9: up to 9× faster vulnerability prioritization

The scanning and remediation core has been refactored for less overhead, safer
process execution, and more reliable results.

| Change | What you get |
|---|---|
| **Up to 9× faster prioritization** | Select the most urgent findings without sorting an entire large report |
| **Scan-only mode** | Generate reports and evaluate CI gates without attempting fixes |
| **SARIF 2.1.0 export** | Export findings for CI integrations, including from saved scans |
| **Configurable scanner timeouts** | Bound each SAST scanner attempt and record execution timing |
| **Stricter scanner handling** | Malformed reports and operational failures fail instead of looking like clean scans |
| **Safer remediation** | Literal Git arguments and commits that stage only remediation files |
| **Smaller runtime dependency set** | The published CLI no longer requires TypeScript or ts-node |
| **Atomic JSON writes** | Readers see complete reports; failed replacement preserves the previous file |

### What “9× faster” measures

A deterministic benchmark with **100,000 findings**, on Node.js 26.8.1:

| Fix limit | Previous full sort | New bounded selection | Speedup |
|---|---:|---:|---:|
| 1 | 14.17 ms | 1.52 ms | 9.33× |
| 10 | 14.56 ms | 1.75 ms | 8.33× |
| 100 | 14.59 ms | 1.79 ms | 8.15× |

These are median timings for **vulnerability prioritization**, not end-to-end scan
speedups. Scanner, registry, and GitHub latency still affect total run time.
Results vary by machine. The benchmark checks that both implementations select
identical findings.

From a source checkout, reproduce with `npm run benchmark`.
See [refactor and performance notes](docs/REFACTOR.md) for implementation details,
test coverage, and why this release stays with TypeScript rather than adding Rust.

## Install

Requires **Node.js 22.12 or newer**.

```bash
npm install -g @devdonzo/warden
warden --version
```

For development:

```bash
npm ci
npm run build
```

## Quick start

Scan and generate reports without attempting fixes:

```bash
warden scan . --scan-only --scanner npm-audit
```

Preview up to two high-severity fixes:

```bash
warden scan . --dry-run --scanner npm-audit --severity high --max-fixes 2
```

Run a scan with CI policy gates and machine-readable output:

```bash
warden scan . --scan-only --ci --json --scanner npm-audit --severity high
```

Open the local console to inspect posture, findings, trends, and artifacts:

```bash
warden console
```

## How it works

```text
scan → prioritize → check policy → apply allowed fixes → open PR → record results
```

- **Watchman** scans dependencies with Snyk, npm-audit, or pip-audit.
- **Engineer** diagnoses selected findings and applies supported dependency fixes.
- **Diplomat** pushes remediation branches and opens PRs when GitHub credentials are configured.
- **Policy gates** enforce approval requirements and CI failure thresholds.
- **Baselines, history, and memory** track regressions, run trends, and recurring packages.

Warden also supports infrastructure advisory workflows through Nmap and optional
Metasploit integrations. Configure authorized targets before using `warden dast`.

## Commands and controls

```bash
warden scan [repository-or-path]
warden dast <target>
warden baseline --create
warden baseline --check --severity high
warden export-sarif --input scan-results/scan-results.json --output results.sarif
warden console
warden validate
warden bootstrap-ci --scanner npm-audit --severity high
```

Useful scan flags:

| Flag | Behavior |
|---|---|
| `--scan-only` | Generate reports without remediation attempts |
| `--dry-run` | Preview selected fixes without applying them |
| `--scanner <type>` | Choose `snyk`, `npm-audit`, `pip-audit`, or `all` |
| `--severity <level>` | Minimum severity for fix selection |
| `--max-fixes <n>` | Limit remediation attempts; zero selects no fixes |
| `--scan-timeout <ms>` | Timeout per SAST scanner attempt |
| `--ci` | Apply configured CI policy gates and failure exit codes |
| `--json` | Write the run result as JSON |
| `--approval-token approved` | Satisfy the configured remediation approval gate |

`all` retains the existing fallback-chain behavior; it does not aggregate every
scanner. Explicit npm-audit and pip-audit selections run the requested scanner.
Snyk retries and fallback attempts can make total run time exceed one attempt’s
timeout. `--severity` controls fix selection; CI failure thresholds live in policy configuration.

## Accepted-risk baselines

Create and commit a baseline from a saved scan:

```bash
warden baseline --create
git add .warden-baseline.json
```

After a new scan, check for new or worsened high-risk findings:

```bash
warden baseline --check --severity high
```

## SARIF and durable reports

Successful orchestrated scans write `scan-results/warden.sarif` automatically.
You can also export a saved scan without contacting a scanner:

```bash
warden export-sarif --input scan-results/scan-results.json --output results.sarif
```

The SARIF report includes advisory rules, severity levels, stable finding
fingerprints, and dependency manifest locations. It does not invent source line
numbers; infrastructure findings omit manifest locations.

| Artifact | Purpose |
|---|---|
| `scan-results.json` | Normalized findings and SAST execution timing |
| `warden.sarif` | SARIF 2.1.0 output for CI integrations |
| `warden-report.md` | Human-readable operator report |
| `scan-results.html` | HTML report |
| `agent-run-record.json` | Findings, selected fixes, policy reasons, branches, and PRs |
| `warden-approval-request.json` | Approval request when policy blocks remediation |
| `history.json` | Run history and trends |
| `memory.json` | Recurring vulnerable package memory |

Artifacts live in `scan-results/`. The accepted-risk baseline lives separately at
`.warden-baseline.json`. Warden’s JSON artifact contracts are in [`schemas/`](schemas/).

## Configuration

Example `.wardenrc.json`:

```json
{
  "scanner": {
    "primary": "snyk",
    "fallback": true,
    "timeout": 60000,
    "retries": 3
  },
  "fixes": {
    "maxPerRun": 2,
    "minSeverity": "high"
  },
  "policy": {
    "failOnSeverity": "critical",
    "failOnPosture": "critical",
    "requireApprovalAboveSeverity": "high"
  },
  "notifications": {
    "enabled": false,
    "email": {
      "to": ["security@example.com"],
      "from": "Warden <warden@example.com>",
      "provider": "resend",
      "apiKeyEnv": "RESEND_API_KEY"
    }
  }
}
```

Optional environment variables:

```bash
GITHUB_TOKEN=...   # Enables branch pushes and PR creation
SNYK_TOKEN=...     # Authenticates Snyk scans
RESEND_API_KEY=... # Enables configured Resend email notifications
```

Email delivery also supports a generic webhook through
`notifications.email.webhook`.

## Development and verification

Version 1.9 was verified with **170 passing tests across 27 suites**, the coverage
gate, packaged CLI smoke tests, a production-only installation, and SARIF
validation against the OASIS schema. Live authenticated GitHub and external DAST
operations are outside the offline test coverage.

```bash
npm test -- --runInBand
npm run build
npm run smoke
```

Use targeted tests during development. `npm run release:check` performs the full
clean/build/test/package gate when preparing a release.

## Documentation

- [What changed and benchmark details](docs/REFACTOR.md)
- [Changelog](docs/CHANGELOG.md)
- [Copyable CI workflow](docs/EXAMPLE-CI.md)
- [Warden and interactive coding agents](docs/WARDEN-VS-CODEX.md)
- [Contributing](.github/CONTRIBUTING.md)
- [Security policy](.github/SECURITY.md)

Concurrent workflows within a single Node.js process remain unsupported because
workflows still change the process working directory. Atomic files protect
readers from partial writes; history and memory are not a multi-process database.

## License

ISC © [DevDonzo](https://github.com/DevDonzo)

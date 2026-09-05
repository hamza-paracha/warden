# Warden

**Warden is an auditable security remediation agent for teams that want agentic fixes without losing policy, review, and CI control.**

[![npm version](https://img.shields.io/npm/v/@devdonzo/warden?style=for-the-badge)](https://www.npmjs.com/package/@devdonzo/warden)
[![npm downloads](https://img.shields.io/npm/dm/@devdonzo/warden?style=for-the-badge)](https://www.npmjs.com/package/@devdonzo/warden)
[![CI](https://img.shields.io/github/actions/workflow/status/DevDonzo/warden/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/DevDonzo/warden/actions/workflows/ci.yml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg?style=for-the-badge)](https://opensource.org/licenses/ISC)

Coding agents can fix vulnerabilities when you ask them to. Warden turns that ability into a repeatable security workflow:

- Scan a repository or infrastructure target.
- Prioritize the findings that matter.
- Apply safe fixes within configured limits.
- Block risky remediation until approval.
- Open reviewable security PRs.
- Record what happened, why it happened, and what policy allowed or blocked.
- Fail CI when risk crosses your gate.

The product is not "an LLM that fixes code." The product is the control plane around agentic remediation.

## Open Source Status

Warden is public, ISC-licensed, and distributed on npm as
[`@devdonzo/warden`](https://www.npmjs.com/package/@devdonzo/warden).
The repository includes CI, release packaging checks, contribution guidelines,
issue templates, a security policy, machine-readable artifact schemas, and a
copyable downstream GitHub Actions workflow for adopters.

Current public usage signals are tracked in
[`docs/OPEN-SOURCE-MAINTENANCE.md`](docs/OPEN-SOURCE-MAINTENANCE.md).

## Why Not Just Use Codex or Claude Code?

Use Codex or Claude Code when you want an interactive coding partner.

Use Warden when security work needs to happen the same way every time:

- **Continuous**: runs in CI, release gates, and scheduled scans.
- **Governed**: enforces severity gates, posture gates, fix limits, and approval requirements.
- **Auditable**: writes durable artifacts instead of leaving the rationale trapped in chat history.
- **Reviewable**: produces PR context for humans and future agents.
- **Stateful**: tracks baselines, regressions, run history, and recurring vulnerable package memory.

Warden answers the questions that matter after an agent touches a repo:

```text
What broke?
What did we select for remediation?
What changed?
What was blocked?
Why did the agent think this mattered?
Which PRs or reports came out of the run?
```

## What It Does

Warden currently supports:

- SAST dependency scans for Node.js and Python projects.
- DAST-style infrastructure advisory runs.
- `npm-audit`, `pip-audit`, Snyk fallback paths, and mock scanner support for tests.
- Dry-run remediation planning.
- GitHub branch and PR automation when credentials are configured.
- CI policy gates with deterministic exit codes.
- Accepted-risk baselines for regression-only enforcement.
- Local console and human-readable reports.
- Machine-readable artifact contracts in `schemas/`.

## Install

Requires Node.js 22.12 or newer.

```bash
npm install -g @devdonzo/warden
```

For local development:

```bash
npm install
npm run build
```

## Quick Start

Validate your environment:

```bash
warden validate
```

Run a local dry-run scan:

```bash
warden scan . --dry-run --scanner npm-audit --severity high --max-fixes 2
```

Run with CI policy gates:

```bash
warden scan . --ci --json --scanner npm-audit --severity high
```

Create an accepted-risk baseline:

```bash
warden baseline --create
git add .warden-baseline.json
```

Fail only on new or worsened high-risk findings:

```bash
warden baseline --check --severity high
```

Open the local console:

```bash
warden console
```

## Core Commands

```bash
warden scan [repository-or-path]
warden dast <target>
warden baseline --create
warden baseline --check
warden console
warden validate
warden bootstrap-ci
```

Useful flags:

```bash
--scanner <snyk|npm-audit|pip-audit|all>
--severity <low|medium|high|critical>
--max-fixes <n>
--dry-run
--json
--ci
--approval-token approved
```

## Output Artifacts

Warden writes durable run artifacts into `scan-results/`:

| Artifact | Purpose |
|---|---|
| `scan-results.json` | Normalized scanner output |
| `warden-report.md` | Human-readable operator report |
| `scan-results.html` | HTML report |
| `agent-run-record.json` | Agent handoff record with findings, fixes, policy reasons, and why-it-matters context |
| `warden-approval-request.json` | Written when policy blocks risky remediation |
| `history.json` | Longitudinal run history |
| `memory.json` | Recurring vulnerable package memory |
| `.warden-baseline.json` | Committed accepted-risk baseline |

The JSON artifacts have schemas in `schemas/` so other agents, CI jobs, dashboards, and review tools can consume Warden output without scraping terminal logs.

## The Agent Handoff Record

`agent-run-record.json` is the artifact that makes Warden useful beyond a single chat session. It captures:

- What broke: scan summary and top findings.
- What changed: selected vulnerability IDs, attempted fixes, applied fixes.
- What was produced: branches, PR URLs, reports, and advisories.
- Why it matters: risk score, posture, and remediation summary.
- Why it was allowed or blocked: policy decision and warnings.

That lets another agent, a reviewer, or future you understand why a security change happened.

## Configuration

Example `.wardenrc.json`:

```json
{
  "scanner": {
    "primary": "snyk",
    "fallback": true
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

Environment variables:

```bash
GITHUB_TOKEN=...  # enables branch push and PR creation
SNYK_TOKEN=...    # recommended for Snyk scans
RESEND_API_KEY=... # optional, enables email notifications
```

Email notifications can also target a generic webhook by setting
`notifications.email.webhook`; Warden posts a normalized email payload that can
be routed through Zapier, Make, SES Lambda, or an internal notification service.

## Release Confidence

Warden has a release gate that checks behavior, not just compilation:

```bash
npm run release:check
```

It builds the package, runs tests, executes a smoke test against mock scanner output, verifies the expected artifact bundle, and checks the npm package contents.

## Example CI

Warden can generate a downstream GitHub Actions workflow:

```bash
warden bootstrap-ci --scanner npm-audit --severity high
```

For a copyable workflow file, see [`docs/EXAMPLE-CI.md`](docs/EXAMPLE-CI.md).

## Positioning

Warden is for teams that want agentic security remediation but need operational guarantees:

```text
scan -> triage -> policy check -> fix safe issues -> open PR -> record rationale -> pass/fail CI
```

That loop is the product.

## License

ISC © [DevDonzo](https://github.com/DevDonzo)

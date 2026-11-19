# Warden

**A supply-chain firewall for coding agents and dependency PRs.**

Warden checks what each npm release does that the previous one did not, blocks
hallucinated and typosquatted packages before an agent installs them, and verifies
dependency fixes with fresh scans, isolated tests, and signed evidence. No LLM,
account, or hosted service required.

[![npm version](https://img.shields.io/npm/v/@devdonzo/warden?style=for-the-badge)](https://www.npmjs.com/package/@devdonzo/warden)
[![CI](https://img.shields.io/github/actions/workflow/status/hamza-paracha/warden/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/hamza-paracha/warden/actions/workflows/ci.yml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg?style=for-the-badge)](LICENSE)

> **Status:** the supply-chain guard, agent integration, and attestations are on
> `main` and unreleased. Dependency verification shipped in the v1.10.0 GitHub source
> release. npm still serves **v1.8.0**, which has neither. Install from source below.

## Why

`npm audit` only knows about attacks that already have an advisory. The 2025
`chalk`/`debug` maintainer hijack and the Shai-Hulud worm shipped clean-looking
releases that installed for hours before any advisory existed. Meanwhile, coding
agents add dependencies with nobody watching, sometimes picking names that don't
exist. Attackers can register those names later ("slopsquatting").

Warden asks a different question: **what does this release do that the last one
didn't?** It compares each release with its predecessor and reports only new
behavior, so established packages stay quiet.

```text
$ warden guard "npm install reqeusts colros chalk@5"
Verdict: BLOCK
BLOCK reqeusts@latest
  - [critical] reqeusts does not exist on the registry. Coding agents often invent
    package names, and attackers register them later (slopsquatting).
BLOCK colros@latest
  - [critical] colros does not exist on the registry. ... Did you mean colors?
ALLOW chalk@5.6.2 (published 2025-09-08, by sindresorhus, no provenance, diffed against 5.6.0)
```

## Install

Requires **Node.js 22.12 or newer**.

```bash
git clone https://github.com/hamza-paracha/warden
cd warden
npm ci
npm run build
npm install -g .
warden --version
```

`npm install -g @devdonzo/warden` installs the older v1.8.0 scanner and remediation
CLI without the features in this README's first sections.

## Quick start

```bash
warden inspect chalk lodash@^4 @scope/pkg@1.2.3     # before installing
warden review . --base origin/main                  # any dependency PR
warden agent-setup claude devin                     # guard your coding agents
```

| Command | Answers | Exit codes |
|---|---|---|
| `warden inspect <specs...>` | Is it safe to install these packages? | 0 allow/warn · 2 block · 3 incomplete |
| `warden review [repo] --base <ref> [--head <ref>]` | Is anything this lockfile change installs risky? | 0 passed · 2 failed · 3 incomplete |
| `warden guard "<command>"` | Would this shell command install something risky? | 0 allow/warn · 2 block |
| `warden verify [repo] --base --head --advisory --test-command` | Did this fix remove the advisory without breaking tests or adding risk? | 0 passed · 2 failed · 3 incomplete |
| `warden attest sign / check` | Can a reviewer trust this evidence without rerunning it? | 0 valid · 1 invalid |

`review` reads both lockfiles with `git show`. It never checks out, installs, or
runs repository code, so it is safe on untrusted pull requests, including
Dependabot and Renovate PRs.

## What Warden checks

Release contents are downloaded, verified against their integrity hash, and read
entirely in memory; nothing from a package is written to disk or executed. Code
signals count only when they are new compared with the same file in the previous release.

| Signal | Severity |
|---|---|
| Package name does not exist (hallucinated) | critical |
| Lockfile changes the integrity hash of an already-locked version, or disagrees with the registry | critical |
| Tarball install scripts differ from registry metadata (manifest confusion) | critical |
| Newly reads credentials or the environment **and** opens network connections | critical |
| Ships `trufflehog`/`gitleaks`, or runs `curl … \| sh` | critical |
| Name imitates a popular package and has under 50,000 weekly downloads | high |
| Released less than 24 hours ago (configurable) | high |
| Previous release had provenance; this one does not | high |
| `preinstall`/`install`/`postinstall` script added or changed | high |
| Newly reads `.npmrc`, SSH keys, cloud credentials, or tokens; serializes `process.env` | high |
| Overrides `fetch`/`XMLHttpRequest`, touches `window.ethereum`; obfuscated code; ships a GitHub workflow | high |
| Dependency resolves outside the registry | high |
| New child processes, dynamic code, network access, native binaries, minified rewrites | medium |
| New publisher on a recent release; brand-new package | medium |

A signal at or above `blockAt` (default `high`) blocks; `medium` warns. Signals tell
you what to review, not that a package is malware. Type declarations are skipped,
and test or example files are downgraded one level.

In a local test, `warden review` checked all 411 releases in Warden's own
dependency tree in about 9 seconds with no blocks. The 2 warnings were newly shipped
native binaries.

## Coding agents

```bash
warden agent-setup claude devin     # writes project-level config, preserving existing settings
warden agent-setup codex            # prints the ~/.codex/config.toml snippet
```

| Agent | MCP server | Install guard hook |
|---|---|---|
| Claude Code | `.mcp.json` | `.claude/settings.json` (PreToolUse, matcher `Bash`) |
| Devin | `.devin/mcp_config.json` | `.devin/hooks.v1.json` (PreToolUse, matcher `exec`) |
| Codex | `~/.codex/config.toml` (printed, not written) | — |

**Hook.** `warden guard --hook` runs before every shell command. It finds packages
installed or executed by `npm install/add/update`, `npx`, `npm exec`, `npm create`,
`pnpm add/dlx`, `yarn add/dlx`, `bun add`, and `bunx`, checks them, and blocks with
exit code 2 and a reason the agent can act on. Git, URL, and file installs warn
because they bypass registry history. If the registry is unreachable, the hook
allows the install unless `--fail-closed` is set.

**MCP tools.** `warden mcp` serves four tools over stdio:

| Tool | Purpose |
|---|---|
| `check_packages` | Allow/warn/block verdicts with reasons for package specs |
| `check_install_command` | Parse a shell command and check every package it would install |
| `review_dependency_change` | Review the lockfile change between two commits |
| `verify_dependency_fix` | Run the full verification (audit, tests, release review) |

## Policy

Add a `supplyChain` section to `.wardenrc.json`:

```json
{
  "supplyChain": {
    "minReleaseAgeHours": 24,
    "blockAt": "high",
    "allow": ["esbuild", "some-pkg@1.2.3"],
    "diff": true,
    "establishedDownloads": 50000,
    "maxPackages": 300,
    "concurrency": 6
  }
}
```

`review` and `verify` read policy from the **base** revision, so a pull request
cannot allowlist its own dependency. `inspect` accepts `--min-age`, `--block-at`,
and `--no-diff` for one-off overrides.

## Verify dependency fixes

Check a dependency security patch from any developer or coding agent:

```sh
warden verify /path/to/repo --base main --head dependency-fix \
  --advisory GHSA-xxxx-yyyy-zzzz --test-command '["npm","test"]'
```

Warden resolves both commits, snapshots them into disposable workspaces, runs fresh
`npm audit` scans, confirms the target advisory was present before and is gone
after, flags new or worsened findings, runs the tests, and reviews every newly
installed release (`--no-supply-chain` to skip). Docker is the default test runner
with no network access; pull `node:24-bookworm-slim` first, or use
`--test-runner trusted-host` for a repository you trust. A missing scanner, missing
tests, or unavailable runner produces **incomplete**, never a pass. Your working tree
and index are never modified.

Supports single-package npm repositories with v2/v3 lockfiles. See the
[verification guide](docs/VERIFICATION.md).

## Signed evidence

```sh
warden attest keygen                                    # .warden/keys/warden-attest.{key,pub}
warden review . --base main --attest-key .warden/keys/warden-attest.key
warden attest check scan-results/review/dependency-review.intoto.json \
  --key .warden/keys/warden-attest.pub
```

`verify` and `review` evidence is wrapped as an in-toto Statement v1 in a DSSE
envelope and signed with Ed25519. Subjects are the base and head commits and their
lockfile SHA-256 digests. Any edit to the evidence invalidates the signature. Keep
the private key out of Git (`.warden/keys/` is ignored). Keyless Sigstore signing is
not implemented.

## CI on pull requests

```yaml
name: Warden dependency review
on:
  pull_request:
    paths: ['package-lock.json']
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-node@v4
        with: { node-version: '24' }
      - run: |
          git clone --depth 1 https://github.com/hamza-paracha/warden /tmp/warden
          cd /tmp/warden && npm ci && npm run build && npm install -g .
      - run: warden review . --base "origin/${{ github.base_ref }}" --head HEAD
      - if: always()
        run: cat scan-results/review/dependency-review.md >> "$GITHUB_STEP_SUMMARY"
```

## Scanning and remediation

Warden's original workflow scans Node.js and Python dependencies, prioritizes
findings, applies fixes your policy allows, and opens GitHub PRs for review:

```text
scan → prioritize → check policy → apply allowed fixes → open PR → record results
```

```bash
warden scan . --scan-only --scanner npm-audit                       # reports only
warden scan . --dry-run --scanner npm-audit --severity high --max-fixes 2
warden scan . --scan-only --ci --json --scanner npm-audit --severity high
warden baseline --create && warden baseline --check --severity high  # accepted-risk baselines
warden export-sarif --input scan-results/scan-results.json --output results.sarif
warden console                                                       # local dashboard
```

- **Scanners:** Snyk, npm-audit, or pip-audit (`--scanner`). `all` is a fallback
  chain, not an aggregate.
- **Policy gates:** severity and posture thresholds, fix limits, and an approval
  requirement (`--approval-token approved` is a workflow signal, not authentication).
- **Reports:** `scan-results/` holds normalized JSON, SARIF 2.1.0, Markdown, HTML, an
  agent run record, history, and recurring-package memory. JSON contracts are in
  [`schemas/`](schemas/).
- **PRs:** set `GITHUB_TOKEN` to push remediation branches and open PRs. `SNYK_TOKEN`
  authenticates Snyk; `RESEND_API_KEY` enables email notifications.
- **Performance:** finding prioritization is up to 9× faster on 100,000-finding
  reports. The figure measures selection only, not end-to-end scans; see
  [refactor notes](docs/REFACTOR.md).

<details>
<summary>Example scanner configuration</summary>

```json
{
  "scanner": { "primary": "snyk", "fallback": true, "timeout": 60000, "retries": 3 },
  "fixes": { "maxPerRun": 2, "minSeverity": "high" },
  "policy": {
    "failOnSeverity": "critical",
    "failOnPosture": "critical",
    "requireApprovalAboveSeverity": "high"
  }
}
```

</details>

Infrastructure advisory workflows through Nmap and optional Metasploit integrations
are available with `warden dast <target>` for authorized targets.

## Limits

- npm registry and npm v2/v3 lockfiles only. pnpm/yarn lockfiles, private registry
  authentication, and monorepos are not supported yet.
- Release analysis compares what changed in the code; it doesn't run it. A payload
  fetched only at runtime from a clean-looking release shows up as a new network
  capability, not as the payload itself.
- The typosquat list is bundled and offline; weekly download counts come from
  `api.npmjs.org`.
- Passing checks do not certify that software is secure. Human review decides
  whether to merge.

## Development

```bash
npm ci
npm run build
npm test -- --runInBand
npm run smoke
```

The current source passes **288 tests across 34 suites**. CI runs builds, tests with
coverage gates, formatting, and packaged CLI smoke tests on Node.js 22 and 24, plus
a real dependency-patch job with host and Docker test runners. Unit tests use an
in-memory registry and never hit the network. `npm run release:check` runs the full
release gate.

| Directory | Responsibility |
|---|---|
| `src/supply-chain/` | Registry client, in-memory tarball reader, release diffing, lockfile review, policy |
| `src/guard/`, `src/mcp/` | Install-command parsing, agent hooks and setup, MCP server |
| `src/attestation/` | DSSE/in-toto signing and verification |
| `src/verification/` | Dependency patch comparison, test runners, and evidence |
| `src/scanners/`, `src/agents/` | Scanner adapters, dependency fixes, Git branches, and PRs |
| `src/workflows/`, `src/services/`, `src/utils/` | Orchestration, process execution, policy, and reports |
| `__tests__/`, `scripts/` | Tests, fixtures, smoke checks, and benchmarks |
| `schemas/`, `docs/`, `website/` | Artifact contracts, guides, and the project website |

## Documentation

- [Supply-chain guard, agents, and attestations](docs/SUPPLY-CHAIN.md)
- [Dependency fix verification](docs/VERIFICATION.md)
- [Changelog](docs/CHANGELOG.md)
- [Product direction](docs/PRODUCT-DIRECTION.md) and [current priorities](docs/IMPROVEMENTS.md)
- [Copyable scanner CI workflow](docs/EXAMPLE-CI.md)
- [Contributing](.github/CONTRIBUTING.md) · [Security policy](.github/SECURITY.md)

## License

ISC © [DevDonzo](https://github.com/DevDonzo)

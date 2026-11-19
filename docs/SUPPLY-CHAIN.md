# Supply-chain guard

`npm audit` only knows about advisories that already exist. The most damaging npm
incidents of 2025 (the `chalk`/`debug` maintainer compromise and the self-spreading
Shai-Hulud worm) were malicious *releases* that installed cleanly for hours before
any advisory was published. And coding agents now add dependencies with no human
watching, sometimes choosing package names that do not exist ("slopsquatting").

Warden answers a different question: **what does this release do that the previous
one did not?** It needs no LLM, account, or hosted service.

## What is checked

| Signal | Severity | Source |
|---|---|---|
| Package does not exist (hallucinated name) | critical | registry |
| Name imitates a popular package and is not established | high | local list + weekly downloads |
| Release younger than `minReleaseAgeHours` (default 24h) | high | registry |
| Provenance present on the previous release, missing now | high | registry |
| Lifecycle script (`preinstall`/`install`/`postinstall`) added or changed | high | registry + tarball |
| Tarball `package.json` scripts differ from registry metadata (manifest confusion) | critical | tarball |
| Newly reads credentials (`.npmrc`, `.ssh`, cloud keys, tokens) | high | code diff |
| Newly serializes `process.env` | high | code diff |
| Network access plus credential/env reads in the same release | critical | code diff |
| Overrides `fetch`/`XMLHttpRequest`, touches `window.ethereum` | high | code diff |
| Obfuscated code, or readable source replaced by a minified blob | high / medium | code diff |
| Ships `trufflehog`/`gitleaks`, a GitHub workflow, or `curl … \| sh` | critical / high | code diff |
| New child processes, dynamic code, network access, native binaries | medium | code diff |
| New publisher on a recent release; brand-new package; deprecation | medium / low | registry |
| Lockfile changes the integrity of an already-locked version | critical | lockfile |
| Lockfile integrity differs from the registry | critical | lockfile + registry |
| Dependency resolves outside the registry, or without integrity | high / medium | lockfile |

Code signals are reported only when they are **new** relative to the same file in the
previous release, so established packages stay quiet. Tarballs are verified against
their SRI hash and read entirely in memory; nothing from the package is written to
disk or executed. Type declarations are skipped and test/example files are downgraded.

Verdicts: a signal at or above `blockAt` (default `high`) blocks; `medium` warns.
Signals are review prompts, not malware verdicts.

## Commands

```sh
# Before installing
warden inspect chalk lodash@^4 @scope/pkg@1.2.3
warden guard "npm install left-pad && npx create-vite@latest app"

# Any dependency PR: Dependabot, Renovate, a human, or an agent
warden review . --base origin/main --head HEAD

# Dependency security fixes: advisory resolved + tests + release review
warden verify . --base main --head fix --advisory GHSA-xxxx-yyyy-zzzz --test-command '["npm","test"]'
```

Exit codes: `0` allowed/passed, `2` blocked/failed, `3` incomplete (for example the
registry was unreachable). `review` writes `scan-results/review/dependency-review.{json,md}`.

## Coding agents

```sh
warden agent-setup claude devin     # project-level MCP server + pre-install hook
warden agent-setup codex            # prints the ~/.codex/config.toml snippet
```

- **Hook:** `warden guard --hook` runs before every shell command. If the command
  installs or executes registry packages (`npm i`, `npx`, `pnpm add/dlx`, `yarn add/dlx`,
  `bun add`, `bunx`, `npm create`), they are checked and blocked with exit code 2 and a
  reason the agent can read. Registry outages fail open unless `--fail-closed` is set.
- **MCP:** `warden mcp` exposes `check_packages`, `check_install_command`,
  `review_dependency_change`, and `verify_dependency_fix` so agents can check before
  they act and verify their own dependency patches.

Files written: Claude Code uses `.mcp.json` and `.claude/settings.json`; Devin uses
`.devin/mcp_config.json` and `.devin/hooks.v1.json`. Existing settings are preserved.

## Policy

Add to `.wardenrc.json`:

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

`review` and `verify` read policy from the **base** revision, so a pull request cannot
allowlist its own dependency.

## Signed evidence

```sh
warden attest keygen                       # .warden/keys/warden-attest.{key,pub}
warden review . --base main --attest-key .warden/keys/warden-attest.key
warden attest check scan-results/review/dependency-review.intoto.json \
  --key .warden/keys/warden-attest.pub
```

Evidence is wrapped as an [in-toto Statement v1](https://github.com/in-toto/attestation)
inside a [DSSE](https://github.com/secure-systems-lab/dsse) envelope and signed with
Ed25519. Subjects are the base/head commits and lockfile SHA-256 digests. Keep the
private key out of Git (`.warden/keys/` is ignored). Keyless Sigstore signing is not
implemented.

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
      - run: npm install -g @devdonzo/warden
      - run: warden review . --base "origin/${{ github.base_ref }}" --head HEAD
      - if: always()
        run: cat scan-results/review/dependency-review.md >> "$GITHUB_STEP_SUMMARY"
```

No install step is needed: `review` reads lockfiles with `git show` and never runs
repository code.

## Limits

- npm registry and npm v2/v3 lockfiles only; pnpm/yarn lockfiles and private registry
  authentication are not supported yet.
- Static analysis of what changed, not execution tracing. A payload that is only
  fetched at runtime from a clean-looking release will show up as a new network
  capability, not as the payload itself.
- The popular-package list for typosquats is bundled and offline; weekly downloads
  come from `api.npmjs.org`.

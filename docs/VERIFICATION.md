# Verify a dependency fix

Warden checks an npm dependency patch from any developer or coding agent and
writes a reviewable evidence bundle. It uses fresh npm-audit reports, identifies
the requested advisory, compares new/resolved/worsened findings, and runs the
candidate's configured tests.

This is the initial npm-only implementation. A passing result means its configured
checks passed; it does not certify that all vulnerabilities or functional bugs are absent.

## Quick start

Use a local Git repository with committed `package.json` and `package-lock.json`
at both revisions. Workspaces, submodules, symlinks, and lockfiles older than v2
are outside the initial scope. Dirty working files are left alone: the verifier
exports the requested commits to disposable directories.

The verifier is available in the v1.10.0 GitHub source release. npm still serves
v1.8.0, which does not include this command. From a source checkout, run `npm ci`
and `npm run build`, then invoke `node /path/to/warden/dist/index.js` in place of
`warden` below.

Pull the test container image once:

```sh
docker pull node:24-bookworm-slim
```

Then verify a patch:

```sh
warden verify /path/to/repository \
  --base main --head dependency-fix \
  --advisory GHSA-xxxx-yyyy-zzzz \
  --test-command '["npm","test"]' \
  --output /path/to/evidence
```

Replace the example advisory with the GHSA ID from the actual npm-audit report.
Numeric npm source IDs are also accepted. Multiple target IDs can follow
`--advisory`. The test command is a JSON argument array, not a shell expression.

The default runner requires an existing Docker daemon and pre-pulled image.
It uses separate containers for dependency installation and tests. Installation
uses `npm ci --ignore-scripts`, with network access to fetch dependencies;
tests run without network access. Containers have resource limits, dropped Linux
capabilities, no host credentials, a read-only root filesystem, and access only
to the disposable candidate workspace. Failed runs attempt to remove their
containers. Docker is an execution boundary, not a complete defense against
container/runtime vulnerabilities.

For a repository you trust, you can explicitly opt into host execution:

```sh
warden verify . --base main --head dependency-fix \
  --advisory GHSA-xxxx-yyyy-zzzz \
  --test-command '["npm","test"]' --test-runner trusted-host
```

**`trusted-host` runs repository test code on your machine.** Environment filtering
is not a sandbox; that code can still access files permitted to your OS user.
Use the container runner or stronger isolation for untrusted code. Warden never
silently falls back to host execution when Docker is unavailable.

Installation scripts are disabled in both modes. Projects that require native
build/install hooks may report incomplete installation or failing tests. A known,
trusted test command can perform required setup explicitly inside its chosen
execution boundary. Do not run untrusted patches with CI write credentials or
use privileged `pull_request_target` execution for untrusted source.

## Results

| Exit | Result | Meaning |
| --- | --- | --- |
| 0 | passed | Target was observed in base and removed in candidate; tests passed; no new/worsened findings at the configured severity |
| 2 | failed | Target remains, tests fail, or new/worsened findings cross the policy threshold |
| 3 | incomplete | Missing/invalid evidence, unsupported project, missing tests, scanner/install failure, timeout, unavailable runner, or changed dependency files during verification |

The default regression threshold is `high`; override with `--severity`.
Pre-existing unrelated findings are listed separately and do not automatically
fail the comparison. A missing target in the base is incomplete, never evidence
of a successful fix. Two scans use the same local npm version and explicit public
registry, but the live advisory database may change between requests.

Evidence files:

- `verification.json`: immutable commit identities, changed file paths,
  manifest/lockfile hashes, targets, normalized findings, comparison, tool
  version, command records, stdout/stderr, and per-check outcomes.
- `verification.md`: reviewer summary for the pull request (see below).
- `verification-summary.json`: small machine-readable summary.

## Reviewer summary

`verification.md` is written so a reviewer can judge the patch from the pull request
alone, without installing anything. It lists the changed package versions (direct
dependencies first), each target advisory in the base and candidate, the test command
and outcome, other new or resolved findings, the reasons for any failure, the
limitations of this run, and where the evidence is. Pass `--evidence-url <url>` to
link the published evidence, for example the CI run that uploaded it.

This is the passing result from CI's live check, which patches lodash 4.17.4 to 4.18.1
(abridged):

```markdown
**Result: PASSED**. Every target advisory is gone from the candidate, no new or worsened findings reached high, and the candidate's tests passed.

| Package | Base | Candidate | Scope |
| --- | --- | --- | --- |
| lodash | 4.17.4 | 4.18.1 | direct |

| Advisory | Package | Base | Candidate |
| --- | --- | --- | --- |
| GHSA-JF85-CPCP-J695 | lodash | present (critical) | resolved |
| GHSA-35JH-R3H4-6JHM | lodash | present (high) | resolved |
| (7 more) | lodash | present | resolved |

`npm test` on trusted-host: **passed** (exit 0)
```

An incomplete result never reads like a pass. The same job verifies those nine
advisories against a base that is already patched. Warden can't show the patch fixed
anything, so it reports:

```markdown
**Result: INCOMPLETE**. Warden could not finish verifying this patch, so it is **unverified**. Don't treat this as a pass; see **What stopped it** below.

| Advisory | Package | Base | Candidate |
| --- | --- | --- | --- |
| GHSA-JF85-CPCP-J695 | - | not found | not verifiable |

`npm test`: **not run**

## What stopped it

- Requested advisory was not observed in the base; remediation is unverified.
```

Both full summaries appear in the job summary of CI's `verification-container` job, and
the evidence bundles are uploaded as the `verification-evidence` artifact. To show the
summary on your own dependency pull requests:

```yaml
- run: >
    warden verify . --base "origin/${{ github.base_ref }}" --head HEAD
    --advisory GHSA-xxxx-yyyy-zzzz --test-command '["npm","test"]'
    --output warden-evidence
    --evidence-url "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
- if: always()
  run: cat warden-evidence/verification.md >> "$GITHUB_STEP_SUMMARY"
- if: always()
  uses: actions/upload-artifact@v4
  with:
    name: warden-evidence
    path: warden-evidence
```

Each artifact is written atomically. Treat the JSON as local, unsigned evidence,
not a signed attestation. Logs/test output can include repository-controlled
content; inspect them before public sharing. Files can contain absolute temporary
paths that no longer exist after cleanup.

The initial scanner always uses the public npm registry and does not forward
private-registry credentials. Repo `.npmrc`, environment files, and files with
credential-like names are excluded from exported workspaces. Projects requiring
those files may need manual review. This is an intentionally narrow scope, not
complete monorepo or private-registry support.

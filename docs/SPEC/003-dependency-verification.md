# SPEC 003: Verify a dependency-remediation change

Status: initial npm implementation in v1.10.0 source; see `docs/VERIFICATION.md` for supported scope and known boundaries.

## Problem

A dependency patch can update a version and pass tests while leaving the intended advisory unresolved. Reviewers need comparable scans and explicit test/provenance records before making a decision.

## Initial scope

- One npm repository with `package.json` and `package-lock.json`.
- Existing immutable base and head commits, resolved from user-supplied Git refs.
- One or more explicitly supplied target advisory IDs.
- One explicit test command using an argument array, with a timeout.
- npm-audit scanner using the same scanner configuration for both revisions.
- Versioned JSON and Markdown output; no LLM integration or automatic merges.

CLI:

```text
warden verify --base <ref> --head <ref> --advisory <id> --test-command '["npm","test"]'
```

Default runner is Docker; `--test-runner trusted-host` explicitly opts into running trusted repository code on the host.

## Required behavior

1. Resolve revisions and record immutable commit SHAs; reject invalid refs and unsupported repository scope.
2. Prepare disposable, isolated workspaces without checking out over or cleaning the user's working tree. Keep scanner/test execution out of the user's environment secrets.
3. Treat installation and test scripts as executable repository content. Execute them only in an appropriate isolated environment for the trust level; never run untrusted PR code with write credentials or on a privileged `pull_request_target` workflow.
4. Perform fresh base and candidate scans with the same tool/version/options and record timestamps. A cached old baseline alone is insufficient evidence of a fix.
5. Record lockfile hashes, scanner identity/version, repository scope, commands, and execution status. Preserve results for human inspection; do not describe live advisory responses as perfectly reproducible.
6. Compare stable advisory/package/ecosystem identities. A version bump must not turn a still-present advisory into a resolved finding merely because the installed version changed.
7. Confirm each requested target was actually observed in the base. Missing targets are unverified, not automatically fixed.
8. Run the configured tests against the candidate and persist their outcome. Missing/skipped tests are incomplete, not passing.
9. Identify target findings resolved/remaining and other new/worsened findings. Changed scanner coverage or missing manifest scope makes the comparison incomplete.
10. Apply documented severity/regression policy and produce pass/fail/incomplete with explicit reasons. Emit a nonzero exit status for incomplete evidence and failed checks; specify distinct stable codes in the implementation.
11. Write evidence atomically. Include failures and incomplete checks in the bundle; do not replace a failed scan with an empty successful result.
12. Clean up owned temporary workspaces without deleting user data. Never push, commit user changes, or merge as part of verification.

## Acceptance tests

- A vulnerable base and fixed candidate with passing tests produce a complete pass.
- A version bump that still contains the same target advisory fails.
- A newly introduced high/critical finding fails the configured policy.
- An existing unrelated accepted finding is identified separately from a regression.
- Absent target in base, missing tests, timeout, scanner failure, malformed output, or incompatible coverage cannot pass.
- Failed tests fail the result even when the security finding disappears.
- Base/head provenance and lockfile hashes appear in JSON/Markdown.
- Repository paths with spaces and hostile-looking Git ref text remain literal arguments.
- The user's branch, index, tracked edits, and untracked files remain unchanged.
- Fixture tests are deterministic with mocked advisory responses; optional live smoke checks are explicitly separate and use maintainer-controlled repositories.

## Boundaries

The result verifies configured checks, not the absence of every vulnerability or business regression. Human review decides whether to merge. Signed attestations, hosted execution, Python verification, monorepos, reachability analysis, and arbitrary code-fix validation are later decisions after the initial pilot.

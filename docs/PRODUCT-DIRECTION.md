# Warden direction: dependency remediation verification

Research date: October 15, 2026.
User priority: a useful tool with real users; portfolio value is secondary.
Status: initial npm verification milestone implemented in v1.10.0 source; npm publication and maintainer pilots remain pending. This does not establish product-market fit.

## Recommendation

Build a small, local-first verifier for dependency-remediation changes, usable after a human, coding agent, Dependabot, or Renovate prepares a patch.

The question it answers is: **Did this dependency change remove the intended finding, introduce other findings, and pass the configured tests?**

Initial audience: maintainers of small Node.js repositories who review dependency patches and want one inspectable evidence bundle without adding an LLM provider. Start with npm; reuse Python scanning later after the npm workflow is dependable.

This is the best next experiment for the existing project because scanner adapters, baseline comparison, safe process execution, JSON/SARIF artifacts, and remediation verification already exist. It keeps the engineering scope small. It is a recommendation, not a claim that competitors cannot do verification.

## What the research changes

| Existing product | Documented capability | Consequence for Warden |
| --- | --- | --- |
| Dependabot | Opens security-update PRs, selects patched versions, supports grouped security updates | Another dependency-update bot has a weak pitch |
| Renovate | Configurable update workflows and Dependency Dashboard approvals | Approval settings alone are insufficient differentiation |
| GitHub Dependency Review Action | Reviews dependency changes and can fail PRs based on vulnerability severity | A generic dependency regression gate is already available |
| GitHub coding agents | Generated-code security validation, dependency checks, and attempted fixes | Generic AI-assisted security remediation overlaps platform features |
| Snyk Delta | Compares snapshots and gates on new vulnerabilities | Baseline/delta comparisons are an established feature |
| Semgrep CI | Supports diff-aware scanning using a baseline reference | “Only report new findings” is not a unique product proposition |

Primary sources:

- [Dependabot security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)
- [Renovate Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/)
- [GitHub Dependency Review Action](https://github.com/actions/dependency-review-action)
- [GitHub agent security validation](https://docs.github.com/en/copilot/concepts/agents/about-third-party-coding-agents)
- [Snyk Delta](https://github.com/snyk-tech-services/snyk-delta)
- [Semgrep CI configuration](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs)

These documents establish feature overlap. They do not establish customer demand, comparative accuracy, or a missing feature in every competing product.

## Focus worth testing

A portable, inspectable record that brings together:

1. Exact base and candidate Git revisions and changed dependency files.
2. Comparable before/after scanner results, with scanner identity, versions, timing, and configuration.
3. Intended advisory IDs and explicit resolved, remaining, new, and worsened findings.
4. Test command, execution status, exit code, duration, and output location.
5. A concise reviewer summary and versioned machine-readable JSON.
6. A clear pass, fail, or incomplete outcome with reasons.

The attraction is fewer manual verification steps across tools. Do not claim superior vulnerability detection: the underlying scanners supply the findings. No LLM subscription should be needed for the initial npm workflow; registry/advisory network access is still required.

## What exists today

- npm-audit, pip-audit, and Snyk scanner adapters.
- Baseline snapshots and comparisons for new/resolved/worsened findings.
- Severity/posture policy gates and an explicit remediation approval flag.
- JSON, Markdown, HTML, and SARIF reports.
- Dependency-update fixers with test execution and Git/PR integration.
- Bounded process execution and atomic artifact writes.

Relevant implementation: `src/utils/baseline.ts`, `src/utils/policy.ts`, `src/utils/reports.ts`, `src/services/process.ts`, `src/agents/engineer/fixer.ts`, and `src/workflows/sast-workflow.ts`.

## Boundaries and gaps before broader adoption

- The initial `warden verify` command now checks committed single-package npm changes and writes evidence. Python, monorepos, and private registry authentication remain outside scope.
- Legacy scan run records are separate from the new verification evidence. Neither is a signed attestation.
- A passing test command does not prove the intended advisory disappeared. A post-change scan must check that explicitly.
- Scanner failures, malformed output, missing tests, incompatible scanner configurations, and unscanned packages must prevent a complete pass.
- The existing `--approval-token approved` flag is a workflow signal, not authenticated authorization or tamper-resistant human approval.
- JSON reports are inspectable artifacts, not cryptographically signed attestations or compliance certification.
- Passing checks cannot certify that software is secure or that an update is functionally compatible in untested behavior.
- Code uses process-wide working-directory changes; parallel verification must use isolated processes/workspaces or remove that coupling.

## First milestone

The bounded implementation follows [SPEC 003](SPEC/003-dependency-verification.md); see [the usage guide](VERIFICATION.md). Support one npm repository, one configured test command, two immutable Git revisions, and an explicit target advisory. Produce JSON and Markdown evidence. Keep patch generation and automatic merging outside this first milestone.

Do not add a dashboard, model orchestration, more agent personas, broad code-vulnerability detection, reachability claims, or a language rewrite for this experiment. Existing DAST support remains available but is outside this focus.

## Adoption decision

Treat repeated use by maintainers as the goal. Start with a manual walkthrough of the evidence report and existing scan/test steps before expanding the CLI. If three pilot maintainers cannot identify a recurring review task where this improves on their current checks, revise the problem or stop the expansion. Do not count npm downloads as active users. Pilot targets and measurements are goals, not existing traction.

## Validation before expansion

1. Use pinned fixture repositories to test a successful fix, an unresolved advisory, a new high-severity finding, failing tests, missing tests, scanner failure, and mismatched scope.
2. Verify the same patch regardless of whether a developer or coding agent authored it.
3. Pilot on three maintainer-controlled repositories with real dependency PRs.
4. Measure time from “patch ready” to a reviewable decision, recording manual steps, total elapsed time, setup effort, and reviewer corrections.
5. Ask maintainers whether they reuse the tool on their next dependency PR. Repeat usage is more meaningful than npm downloads.
6. Compare against existing GitHub checks and a short scan/test script. Continue only if Warden meaningfully reduces effort or improves review evidence.

No pilot or result above has been completed as part of this research. If maintainers prefer existing checks, keep Warden as a maintained security automation project instead of forcing a larger platform.

## Messaging

Current shipped description:

> A TypeScript security automation CLI with dependency scans, remediation policies, regression baselines, and reviewable pull-request workflows.

Verification description for the v1.10.0 source:

> Verify dependency patches from any developer or coding agent with before/after security findings, test results, and a reviewable evidence bundle.

Resume claims should describe implemented work. Do not describe source-only work as an npm release or claim maintainer adoption before publication and pilots.

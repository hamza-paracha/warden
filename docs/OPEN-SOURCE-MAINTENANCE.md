# Open Source Maintenance

Warden is maintained as a public open-source security automation project.

## Public Project Signals

- Repository: <https://github.com/DevDonzo/warden>
- Package: <https://www.npmjs.com/package/@devdonzo/warden>
- License: ISC
- Primary maintainer: DevDonzo
- Published package versions: 1.0.0 through 1.3.0 on npm; repository release work is currently prepared through 1.8.0.
- Verified npm downloads as of 2026-05-31: 1,195 total since publication and 91 in the previous month.

## Maintenance Surface

The repository includes:

- CI across Node.js 22 and 24.
- Release packaging checks with `npm pack --dry-run`.
- Test coverage for scanners, policy gates, baselines, reports, notifications, schema contracts, and CLI flows.
- Machine-readable schemas for scan results, run history, recurring package memory, approval requests, and agent handoff records.
- Contribution guidelines, issue templates, pull request template, code of conduct, and security policy.
- Example downstream GitHub Actions workflow for teams adopting Warden.

## Why This Matters

Security remediation agents can create risk when fixes happen without clear
policy, review, and audit records. Warden focuses on the maintenance layer
around agentic security work: repeatable scans, severity gates, baseline checks,
safe remediation limits, reviewable pull requests, and durable artifacts that
human maintainers and future agents can inspect.

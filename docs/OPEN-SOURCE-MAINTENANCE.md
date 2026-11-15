# Open Source Maintenance

Warden is maintained as a public open-source security automation project.

## Public Project Signals

- Repository: <https://github.com/hamza-paracha/warden>
- Package: <https://www.npmjs.com/package/@devdonzo/warden>
- License: ISC
- Primary maintainer: DevDonzo
- Current GitHub source release: **1.10.0**, including the initial npm dependency
  patch verifier. Source release date: 2026-11-15.
- npm latest remains **1.8.0**; publication of v1.10.0 is pending.
- npm download API snapshot checked on 2026-11-15: **1,877 downloads** for the
  returned interval **2025-05-14 through 2026-11-14**. Downloads include automated
  installations and do not measure unique or active users.

Recheck the public metadata before updating release or download claims:

```sh
npm view @devdonzo/warden version
curl 'https://api.npmjs.org/downloads/point/2025-05-14:2026-11-14/@devdonzo/warden'
```

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

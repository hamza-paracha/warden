# Maintenance priorities

This is the active backlog for the v1.10.0 release. See
[product direction](PRODUCT-DIRECTION.md) for the verifier's scope and
[the changelog](CHANGELOG.md) for shipped changes. The former v1.1 roadmap
and April architecture checklist have been consolidated here because many of
their proposed features already exist.

## 1. Establish confidence in patch verification

- Run the live dependency-patch smoke check with both host and Docker runners
  before publishing a release. CI defines this check; offline unit tests
  do not establish that it passed on a particular release.
- Publish a small, reproducible before/after example with its advisory, commit
  identities, test results, and evidence bundle.
- Keep missing scans, missing tests, unsupported projects, and unavailable runners
  incomplete rather than passing. Maintain the verifier's dedicated coverage gate.
- Keep npm, GitHub release notes, website copy, and installation instructions
  aligned on v1.10.0. Run release checks before each future publication.

## 2. Test the remediation path more deeply

- Cover supported dependency fixes and rollback with temporary Git repositories
  and controlled scanner responses.
- Exercise PR creation and failure handling against a mocked GitHub API, including
  duplicate PRs and push failures.
- Raise coverage gates as these tests land. Existing global thresholds are low;
  passing them alone does not demonstrate broad coverage.

## 3. Reduce maintenance coupling

- Replace process-wide working-directory changes with explicit repository paths
  before supporting concurrent workflows in one process.
- Review duplicated scanner entry points and keep a single normalization contract.
- Keep npm patch verification as the primary product story. Infrastructure/DAST,
  the website, and promotional video are supporting surfaces, not reasons to
  expand the core scope.

## 4. Measure real use

- Walk maintainers through a dependency PR and observe whether the evidence saves
  review steps, then measure repeat use on later PRs.
- Keep npm download counts dated and distinct from active users.
- Reproduce prioritization benchmarks when quoting performance. The existing
  benchmark measures finding selection, not end-to-end scanning speed.

Monorepos, Python verification, private registries, signed attestations, and
additional scanners require separate scoped work. They are not current verifier
capabilities.

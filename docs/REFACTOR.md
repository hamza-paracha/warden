# Core refactor and performance notes

## Changes

- `services/process.ts` executes argument arrays directly with timeouts, output
  limits, cancellation, and explicit accepted exit codes. All five scanners and
  the Git remediation/PR paths now use it. Operational failures cannot be treated
  as successful scans solely because the process wrote JSON to stdout.
- SAST uses the existing scanner registry for a single fallback chain and creates
  scanners only when needed. Timeout, retry, and fallback configuration now reach
  the scanner implementations. Snyk and pip-audit no longer spawn a separate
  version check before each scan.
- The scanner plugin contract is also the legacy Snyk result contract, removing
  duplicate interfaces. The SAST boundary fills optional description/fix fields
  before handing results to the typed workflow.
- The engineer accepts in-memory results as well as saved files. Orchestration
  diagnoses only selected findings and loads the GitHub client only for actual
  remediation with credentials. DAST workflow imports are deferred until use.
- Finding selection uses a bounded heap: O(n log k) time and O(k) extra space,
  where k is the fix limit. Results preserve severity, CVSS, and stable input-order
  tie breaking. Full reports still contain every finding.
- Atomic JSON replacement is shared by scanner snapshots, latest results, run
  history, memory, and SARIF output. Snapshots use unique names even when their
  timestamps collide. Scanner snapshots are serialized once for both writes.
- TypeScript and ts-node are development dependencies; published CLI users run the
  compiled JavaScript without installing a compiler.

## Correctness fixes

Snyk error payloads and malformed pip-audit output previously could become empty,
clean reports. These now fail. Snyk multi-project arrays are parsed instead of
being silently dropped, and retry timing is persisted after scanning completes.
The previous successful artifact is preserved after scanner failure.

An npm audit fix for a parent package is no longer presented as a fixed version
for its child dependency. Such findings remain available for manual remediation.
Git commit messages, repository paths, branches, and DAST output paths are passed
as literal process arguments. Fixers stage only their manifests and lockfile.

CLI scanner/severity values and integer limits are validated. `--scan-only`
generates reports with no remediation attempts. `--scan-timeout` controls each
SAST attempt, and SARIF can be exported both during a run and offline.

## Measurement and Rust decision

The deterministic benchmark compares the previous full-sort implementation with
bounded selection and asserts identical outputs. On the development machine
(Node 26.8.1), 100,000 findings and k values of 1, 10, and 100 took approximately
14–15 ms with full sorting versus 1.5–1.8 ms with bounded selection: roughly
8–9x faster for this operation. These are microbenchmark results, not end-to-end
scan speedups. Use `npm run benchmark` to reproduce on your hardware.

No Rust component was added. The scanned architecture spends time invoking
external scanners, package managers, Git, and APIs. A language rewrite would not
remove those waits. The measured CPU operation is now small and needs no native
build or platform-specific distribution. Reconsider Rust if profiling real large
workloads identifies a substantial remaining CPU bottleneck.

## Verification and boundaries

Tests cover scanner failures and output parsing, timeout/cancellation/buffer
limits, atomic replacement failure, literal Git arguments, targeted staging,
selection equivalence, SARIF identity and locations, and existing app behavior.
The packaged CLI smoke test exercises a target directory containing spaces,
scan-only mode, offline SARIF export, invalid options, artifacts, and policy gates.
DAST process changes are tested without scanning external hosts.

This refactor preserves the console interface, policy semantics, baseline format,
and existing `all` fallback behavior. It does not introduce cached security
verdicts: an unchanged lockfile can still acquire newly disclosed vulnerabilities.
The workflows still use process-wide working-directory changes; concurrent runs
inside one Node process are not supported. Atomic replacement protects readers
from partial files, but history/memory updates are not a multi-process database.
Real registry latency, authenticated GitHub PR creation, and live DAST scans are
outside the offline test coverage.

SARIF follows the [OASIS 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

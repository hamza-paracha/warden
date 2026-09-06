# Changelog

All notable changes to Warden will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] - 2026-09-06

### Added

- Scan-only mode (`--scan-only`) and per-attempt SAST timeout control (`--scan-timeout`).
- Automatic SARIF 2.1.0 reports and offline `export-sarif` command.
- Scanner execution timing, deterministic prioritization benchmark, and refactor notes.
- Regression coverage for process failures, scanner parsing, atomic writes, targeted Git staging, and SARIF export.

### Changed

- Up to 9x faster vulnerability prioritization in the 100,000-finding benchmark; this is not an end-to-end scan speedup.
- Consolidated process execution and scanner fallback handling; removed redundant Snyk/pip-audit version checks.
- Diagnose selected findings in memory and defer optional workflow/GitHub imports.
- Use atomic JSON replacement for scanner output, history, memory, and SARIF.
- Move TypeScript and ts-node to development dependencies.

### Fixed

- Malformed scanner output and operational failures no longer appear as clean scans.
- npm parent dependency fix versions are no longer applied to child packages.
- Parse Snyk multi-project output and persist accurate retry metadata.
- Stop inferring Python severity from description substrings such as "overflow".
- Pass Git and scanner arguments literally, and stage only remediation files.
- Validate CLI scanner, severity, fix limits, and timeout values.

## [1.8.0] - 2026-05-22

### ✨ Added

- **Email Notifications**:
  - Added Resend-backed email delivery for scan, fix, and error notifications
  - Added generic email webhook delivery for Zapier, Make, SES Lambda, or internal routers
  - Added email notification tests and updated configuration examples
- **Downstream CI Documentation**:
  - Added a copyable GitHub Actions workflow for projects that want Warden scans on pull requests, main-branch pushes, schedules, and manual dispatch
  - Added public open-source maintenance notes and packaged them in the npm tarball

## [1.7.0] - 2026-05-12

### ✨ Added

- **Local Warden Console**:
  - Running `warden` now opens a local GUI console by default
  - Added `warden console` and `warden ui` commands
  - Console visualizes scan posture, risk score, findings, baseline deltas, run history, memory hotspots, and artifact readiness
  - Added a branded terminal banner for the main CLI flow
- **Security Baselines**:
  - `warden baseline --create` creates `.warden-baseline.json` from current scan results
  - `warden baseline --check --severity <level>` compares current findings against accepted risk
  - Baseline checks detect new findings, resolved findings, and severity regressions
  - Baseline checks exit with code `2` when a new or worsened finding crosses the configured gate
  - JSON output is available for CI integrations

## [1.6.0] - 2026-05-09

### ✨ Added

- **Python Support (requirements.txt-first)**:
  - `pip-audit` scanner integration
  - Python manifest validation support
  - Python remediation path for exact `requirements.txt` pins
- **Branding Refresh**:
  - New README visual identity and embedded logo asset

### 🔧 Changed

- **README**:
  - Updated to reflect Python support, CI bootstrap, policy gates, memory, and artifacts
  - Added embedded branding asset for GitHub and npm presentation
- **Bootstrap Generator**:
  - `bootstrap-ci` now supports `pip-audit` scanner selection

---

## [1.5.0] - 2026-05-09

### ✨ Added

- **Agentic Assessment Layer**:
  - Risk scoring and security posture classification
  - Immediate actions, manual follow-ups, and strategic improvements per run
  - Markdown and HTML reporting artifacts
- **Policy Gates**:
  - `--ci` mode for deterministic pipeline failures
  - `policy.failOnSeverity` and `policy.failOnPosture` thresholds
  - `policy.requireApprovalAboveSeverity` for human approval on risky fixes
  - Approval request artifact generation
- **Workflow Memory**:
  - Persistent run history with trend detection
  - Recurring vulnerable package hotspot tracking by repository
- **CI Bootstrap**:
  - `warden bootstrap-ci` command for downstream GitHub Actions generation
  - Optional default `.wardenrc.json` generation during bootstrap
- **Fixture-backed Workflow Tests**:
  - Integration coverage for risky-fix blocking
  - Policy evaluation tests
  - Memory tracking tests

### 🔧 Changed

- **SAST Workflow**:
  - Severity thresholds and `maxFixes` are now enforced in actual remediation selection
  - Multiple fixes can be selected in a single run
- **Fix Safety**:
  - npm remediation preserves version ranges
  - lockfile refresh uses `npm install --package-lock-only`
  - dirty repos are blocked instead of being destructively cleaned
- **PR Automation**:
  - Branches are pushed before PR creation
  - Default base branch detection is automatic instead of assuming `main`
- **CLI Output**:
  - `--json` now emits structured run results
  - standard console mode now surfaces posture, trend, policy, memory, and report paths

### 🐛 Fixed

- **npm-audit Auto-fix Path**:
  - stopped fabricating `fixedIn: ["npm audit fix"]`
  - direct upgrades are separated from manual/transitive findings
- **Publish Workflow**:
  - corrected npm package references to `@devdonzo/warden`

---

## [1.3.0] - 2026-02-01

### ✨ Added

- **DAST Integration (Dynamic Application Security Testing)**:
  - **Nmap Scanner**: Network discovery, port scanning, and service detection.
  - **Metasploit Scanner**: Vulnerability verification and controlled exploitation.
  - **Advisory PRs**: Findings generate detailed infrastructure security advisories instead of auto-fixes.
  - **Safety System**: Strict authorization checks, legal warnings, and confirmation prompts.
  - **Configurations**: New `dast` section in `.wardenrc.json`.
  - **Documentation**: Added DAST-GUIDE, NMAP-CONFIG, and METASPLOIT-CONFIG.

### 🔧 Changed

- **CLI**: Added `warden dast` command.
- **Orchestrator**: Updated to support dual-mode operation (SAST/DAST).
- **Scanner Interface**: Extended to support infrastructure targets.

---

## [1.2.0] - 2026-01-29

### ✨ Added

- **Structured Error Types** - New error classes for better debugging:
  - `ScanError` - For scanner-related failures
  - `FixError` - For fix application failures
  - `PRError` - For GitHub PR operation failures
  - `ConfigError` - For configuration issues
  - `ValidationError` - For input validation failures

- **New CLI Commands**:
  - `warden status` - View recent scans and environment status
  - `warden clean` - Remove generated files (scan-results, logs)

- **New CLI Flags**:
  - `--json` - Output results as JSON for CI/CD integration
  - `-q, --quiet` - Suppress non-essential output

- **Centralized Types** - Shared type definitions in `src/types/`

- **GitHub Issue Templates** - Bug report and feature request templates

- **Comprehensive Test Suite** - 60 tests covering:
  - Diplomat Agent (PR generation)
  - Engineer Agent (fix detection)
  - Watchman Agent (npm-audit parsing)
  - Error types (all classes)

### 🔧 Changed

- **Improved Code Organization**:
  - Extracted shared types to `types/` directory
  - Created `errors/` directory for error classes
  - Refactored npm-audit.ts with public helper methods

### 📦 Removed

- `website/` folder (should be separate repo)
- `QUICK_REFERENCE.md` (redundant with README)
- `vercel.json` (not needed)

---

## [1.1.0] - 2026-01-29

### 🔧 Code Quality & Consistency

This release focuses on production readiness with major refactoring for code consistency and improved documentation.

### ✨ Added

- **Comprehensive README** with:
  - npm audit comparison table showing Warden advantages
  - Complete CLI usage examples
  - Environment variables reference
  - Exit codes documentation

### 🔧 Changed

- **Unified Logging System** - Replaced all `console.log/warn/error` calls with centralized logger utility across all agents:
  - Diplomat Agent - consistent logging with agent prefixes
  - Engineer Agent - structured logging for fix operations
  - Watchman Agent - uniform scan progress reporting
  - Snyk Scanner - proper error and warning handling
  - Git Manager - debug-level logging for git operations
  - Spec Loader - integrated with logger system
  - HTML Report Generator - success logging for report generation

### 🐛 Bug Fixes

- **Fixed test failures**:
  - Removed unused `fs` import from validator.test.ts
  - Fixed `getConfig()` to return deep copy preventing external mutation
- **Fixed TypeScript build errors**:
  - Removed unused `oldVersion` variable in Engineer agent
  - Fixed unused `rules` variable in orchestrator
  - Removed unused `envExamplePath` in setup
  - Fixed unused `payload` parameter in notifications
  - Removed unused `id` parameter in progress forEach callback
- **Refactored deprecated code**:
  - Use `Object.hasOwn()` instead of deprecated `hasOwnProperty` in npm-audit scanner

### 📦 Dependencies

- Updated package-lock.json

---

## [1.0.0] - 2026-01-18

### 🎉 Initial Production Release

This is the first production-ready release of Warden with comprehensive improvements for real-world usage.

### ✨ Added

#### CLI & User Experience
- **Professional CLI Interface** using Commander.js
  - `warden scan` - Main scanning command with multiple options
  - `warden validate` - Pre-flight validation checks
  - `warden setup` - Interactive setup wizard
  - `warden init` - Initialize Warden in a repository
- **Comprehensive Logging System**
  - Color-coded console output using Chalk
  - File-based logging with Winston (error.log and combined.log)
  - Verbose mode for debugging (`--verbose` flag)
  - Agent-specific loggers (Watchman, Engineer, Diplomat)
- **Progress Indicators** using Ora for long-running operations
- **Dry Run Mode** to preview changes without applying them (`--dry-run`)

#### Validation & Error Handling
- **Pre-flight Validation System**
  - Environment variable validation
  - System dependency checks (git, node, npm, snyk)
  - Git repository validation
  - package.json validation
- **Comprehensive Error Messages** with actionable suggestions
- **Graceful Degradation** when optional tools are unavailable

#### Configuration & Setup
- **Interactive Setup Wizard** for first-time configuration
- **Repository Initialization** command to set up Warden in any project
- **Flexible Configuration Options**
  - CLI flags override defaults
  - Support for multiple severity levels
  - Configurable scanner selection
  - Max fixes limit

#### Documentation
- **Enhanced README** with:
  - Installation instructions (global and local)
  - Comprehensive usage examples
  - Troubleshooting guide
  - Configuration reference
  - CLI command reference
- **CONTRIBUTING.md** with development guidelines
- **Quick Start Script** for automated setup
- **CHANGELOG.md** for version tracking

#### Testing
- **Unit Tests** for core utilities
  - Validator tests
  - Logger tests
- **Jest Configuration** for TypeScript
- **Test Coverage** reporting

#### Developer Experience
- **Improved Project Structure**
  - Separated CLI from orchestration logic
  - Dedicated utilities directory
  - Better code organization
- **TypeScript Strict Mode** enabled
- **Better Error Handling** throughout the codebase
- **Logging to Files** for debugging

### 🔧 Changed

- **Refactored Main Entry Point** - Simplified index.ts to just load CLI
- **Improved Orchestration** - Moved main logic to dedicated orchestrator module
- **Better Package.json** - Added bin field, keywords, and metadata for npm publishing
- **Enhanced .gitignore** - Added logs directory and log files

### 📦 Dependencies

#### Added
- `commander` - CLI framework
- `chalk` - Terminal string styling
- `ora` - Progress indicators
- `winston` - Logging framework

### 🏗️ Architecture

The Warden now follows a clean architecture with:
- **CLI Layer** - User interface and command handling
- **Orchestration Layer** - Main workflow coordination
- **Agent Layer** - Specialized agents (Watchman, Engineer, Diplomat)
- **Utility Layer** - Shared utilities (logger, validator)
- **Core Layer** - Configuration and rules

### 📋 Commands

```bash
warden scan [repository] [options]  # Scan for vulnerabilities
warden validate                     # Validate environment
warden setup                        # Interactive setup
warden init                         # Initialize in repo
```

### 🎯 Options

- `-v, --verbose` - Enable verbose logging
- `--dry-run` - Preview changes without applying
- `--skip-validation` - Skip pre-flight checks
- `--scanner <type>` - Choose scanner (snyk, npm-audit, all)
- `--severity <level>` - Minimum severity (low, medium, high, critical)
- `--max-fixes <number>` - Maximum fixes to apply

### 🐛 Bug Fixes

- Fixed module import issues with ESM packages (chalk, ora)
- Improved error handling in git operations
- Better handling of missing environment variables

### 🔒 Security

- Added validation for GitHub token permissions
- Improved secrets handling
- Better error messages that don't leak sensitive data

---

## [0.1.0] - 2026-01-16

### Initial Development Release

- Basic agent architecture (Watchman, Engineer, Diplomat)
- Snyk integration for vulnerability scanning
- npm audit fallback
- Automated fix generation
- GitHub PR creation
- Basic CLI support

---

[1.1.0]: https://github.com/DevDonzo/warden/releases/tag/v1.1.0
[1.0.0]: https://github.com/DevDonzo/warden/releases/tag/v1.0.0
[0.1.0]: https://github.com/DevDonzo/warden/releases/tag/v0.1.0

# Warden

**Warden stops AI coding agents and dependency updates from installing malicious npm packages.**

[![CI](https://img.shields.io/github/actions/workflow/status/hamza-paracha/warden/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/hamza-paracha/warden/actions/workflows/ci.yml)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg?style=for-the-badge)](LICENSE)

Security scanners like `npm audit` only catch attacks that are already publicly known.
In 2025, hijacked versions of popular packages (`chalk`, `debug`) and the Shai-Hulud
worm spread for hours before anyone flagged them. AI coding agents make this worse:
they install packages unattended, and sometimes invent package names that attackers
can register later.

Warden checks each package **before it is installed**:

- **Blocks fake and look-alike packages**: names that don't exist, or that imitate popular ones (`lodahs` → `lodash`).
- **Flags suspicious new versions**: compares each release with the previous one and reports new install scripts, code that reads saved passwords or tokens, hidden network calls, obfuscated code, and missing publisher verification.
- **Plugs into coding agents**: works with Claude Code, Devin, and Codex through a pre-install hook and an MCP server.
- **Checks dependency pull requests and fixes**: reviews every package a PR adds, confirms security fixes actually work, and can sign the results.

No AI model, account, or hosted service is needed.

## Install

Requires Node.js 22.12 or newer.

```bash
npm install -g @devdonzo/warden
warden --version
```

## Use it

```bash
warden inspect express lodash@^4          # check packages before installing them
warden review . --base origin/main        # check everything a pull request adds
warden agent-setup claude devin           # protect your coding agents
```

```text
$ warden guard "npm install reqeusts colros chalk@5"
Verdict: BLOCK
BLOCK reqeusts@latest
  - [critical] reqeusts does not exist on the registry. ...
BLOCK colros@latest
  - [critical] colros does not exist on the registry. ... Did you mean colors?
ALLOW chalk@5.6.2 (published 2025-09-08, by sindresorhus, no provenance, diffed against 5.6.0)
```

When an agent tries a blocked install, the command is stopped and the agent gets the
reason. Exit codes: `0` allowed, `2` blocked, `3` couldn't finish checking.

| Command | What it does |
|---|---|
| `warden inspect <packages>` | Checks packages before you install them |
| `warden review [repo] --base <ref>` | Checks every new package version a pull request adds, without running its code |
| `warden guard "<command>"` | Checks the packages an install command would add |
| `warden agent-setup <agents>` | Adds Warden to Claude Code, Devin, or Codex |
| `warden verify` | Confirms a security fix removed the vulnerability and still passes tests |
| `warden attest` | Signs results so reviewers can check they weren't changed |
| `warden scan` | Scans Node.js and Python dependencies and opens fix pull requests |

## How it works

For each new package version, Warden downloads both that version and the one before it,
checks they haven't been tampered with, and compares them without running any of the
package's code. Anything risky that the new version *adds* is reported, so trusted
packages that haven't changed stay quiet. You decide what gets blocked in
`.wardenrc.json`.

The [full guide](docs/SUPPLY-CHAIN.md) covers every check, agent setup, policy options,
GitHub Actions, signed results, and current limits (npm only, and nothing is executed).

## More

- [Supply-chain guide](docs/SUPPLY-CHAIN.md) · [Fix verification](docs/VERIFICATION.md) · [Changelog](docs/CHANGELOG.md)
- Scanning and automatic fix PRs: `warden scan --help`, `warden config --create` for an example configuration, and [example CI](docs/EXAMPLE-CI.md)
- [Contributing](.github/CONTRIBUTING.md) · [Security policy](.github/SECURITY.md)

### Development

```bash
npm ci && npm run build && npm test
```

## License

ISC © [DevDonzo](https://github.com/DevDonzo)

# Security Policy

## Supported Versions

Security fixes target the current source and latest npm release. Older release
lines are not maintained separately.

| Distribution | Current version |
| --- | --- |
| Current source | 1.10.0 |
| npm latest | 1.10.0 |

## Reporting a Vulnerability

If you discover a security vulnerability in Warden, please report it responsibly:

1. **Do NOT** open a public issue
2. Email the maintainer directly (check package.json for contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to expect

- Acknowledgment within 48 hours
- Status update within 7 days
- Fix released as soon as possible

### Scope

This policy covers:
- The Warden CLI tool
- All agents (Watchman, Engineer, Diplomat)
- Configuration parsing
- GitHub API integration
- Scan result handling

### Out of Scope

- Vulnerabilities in dependencies (report to upstream)
- Issues in user-generated content
- Issues in third-party scanners (Snyk, npm)

## Security Best Practices

When using Warden:

1. **Protect your tokens**
   - Never commit `GITHUB_TOKEN` or `SNYK_TOKEN` to git
   - Use environment variables or secret managers
   
2. **Review auto-generated PRs**
   - Always review PRs before merging
   - Warden suggests fixes, humans approve them

3. **Limit permissions**
   - Use fine-grained GitHub tokens
   - Grant minimum required permissions

4. **Keep updated**
   - Update Warden regularly for security patches
   - Run `npm update @devdonzo/warden`

# Warden DAST Guide

## Dynamic Application Security Testing with Nmap & Metasploit

This guide covers how to use Warden's DAST (Dynamic Application Security Testing) capabilities to scan your infrastructure for security vulnerabilities.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Workflow](#workflow)
- [Safety & Legal Considerations](#safety--legal-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

Warden's DAST mode complements traditional SAST (dependency scanning) by adding infrastructure vulnerability detection using:

- **Nmap**: Network discovery and service detection
- **Metasploit Framework**: Vulnerability validation and penetration testing

### Key Differences: SAST vs DAST

| Feature | SAST Mode | DAST Mode |
|---------|-----------|-----------|
| Target | Dependencies (package.json) | Running infrastructure |
| Tools | Snyk, npm audit | Nmap, Metasploit |
| Remediation | Auto-fix PRs | Advisory PRs (manual remediation) |
| Risk Level | Low | **High - requires authorization** |

## Prerequisites

### Required Tools

1. **Nmap** - Network scanner
   ```bash
   # macOS
   brew install nmap

   # Ubuntu/Debian
   sudo apt-get install nmap

   # Windows
   # Download from https://nmap.org/download.html
   ```

2. **Metasploit Framework** (optional, for advanced scanning)
   ```bash
   # macOS
   brew install metasploit

   # Linux
   curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
   chmod 755 msfinstall
   ./msfinstall
   ```

3. **Verify Installation**
   ```bash
   nmap --version
   msfconsole --version
   ```

### Legal Authorization

**⚠️ CRITICAL: Only scan systems you own or have written authorization to test.**

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

## Configuration

### 1. Enable DAST in `.wardenrc.json`

Add the DAST configuration section:

```json
{
  "dast": {
    "enabled": true,
    "targets": [
      {
        "url": "https://staging.myapp.com",
        "description": "Staging Environment",
        "authorized": true,
        "ports": "1-1000"
      },
      {
        "url": "http://localhost:3000",
        "description": "Local Development",
        "authorized": true,
        "ports": "3000,8080,8443"
      }
    ],
    "nmap": {
      "enabled": true,
      "scanType": "standard",
      "portRange": "1-1000",
      "timing": 3,
      "options": ["-sV"],
      "outputFormat": "xml"
    },
    "metasploit": {
      "enabled": false,
      "mode": "scan-only",
      "modules": [],
      "timeout": 60000
    },
    "safety": {
      "requireConfirmation": true,
      "authorizedTargetsOnly": true,
      "disableExploits": true,
      "maxScanDuration": 1800000
    }
  }
}
```

### 2. Configure Targets

Each target requires:

- **`url`** (required): Target URL to scan
- **`authorized`** (required): Must be `true` to scan
- **`description`** (optional): Human-readable description
- **`ports`** (optional): Port range override (e.g., "80,443,8080" or "1-1000")

**Security Note**: Warden will refuse to scan any target without `"authorized": true`.

### 3. Nmap Configuration

See [NMAP-CONFIG.md](./NMAP-CONFIG.md) for detailed Nmap configuration options.

### 4. Metasploit Configuration

See [METASPLOIT-CONFIG.md](./METASPLOIT-CONFIG.md) for detailed Metasploit configuration options.

## Usage

### Basic DAST Scan

```bash
# Scan a specific target
warden dast https://staging.myapp.com

# Scan first authorized target
warden dast https://staging.myapp.com --verbose
```

### Scan Options

```bash
# Verbose output
warden dast https://staging.myapp.com --verbose

# Dry run (preview only)
warden dast https://staging.myapp.com --dry-run

# Nmap only
warden dast https://staging.myapp.com --nmap-only

# Metasploit only (requires Nmap results)
warden dast https://staging.myapp.com --metasploit-only

# Skip safety confirmations (not recommended)
warden dast https://staging.myapp.com --no-confirm
```

## Workflow

### 1. Scan Execution

```bash
$ warden dast https://staging.myapp.com
```

Warden will:
1. Validate configuration
2. Check target authorization
3. Display safety warnings
4. Run Nmap scan (if enabled)
5. Run Metasploit scan (if enabled)
6. Merge results
7. Generate reports

### 2. Results

Scan results are saved to:
- **JSON**: `scan-results/dast/scan-TIMESTAMP.json`
- **Nmap XML**: `scan-results/dast/nmap-TIMESTAMP.xml`
- **Metasploit Output**: `scan-results/dast/msf-output-TIMESTAMP.txt`
- **HTML Report**: `scan-results/scan-report.html`

### 3. Advisory PR

Unlike SAST mode (which creates auto-fix PRs), DAST mode creates **advisory PRs** containing:

- Summary of findings
- Severity breakdown
- Detailed remediation steps for each finding
- Context-specific guidance (e.g., database hardening, firewall rules)

Example PR structure:
```markdown
# DAST Security Advisory

## Summary
- **Total Findings**: 12
- **Critical**: 2
- **High**: 5
- **Medium**: 3
- **Low**: 2

## Findings

### CRITICAL Severity

#### Open TCP port 3306 - mysql
- **Host**: staging.myapp.com
- **Port**: 3306
- **Service**: mysql (5.7.32)

**Description**: MySQL database exposed to public internet

**Remediation**:
1. Implement firewall rules to restrict access to trusted IPs
2. Enable authentication with strong passwords
3. Use VPN or SSH tunneling for remote access
4. Update to latest patch version
...
```

### 4. Manual Remediation

Since infrastructure fixes require manual intervention:

1. Review the advisory PR
2. Prioritize Critical and High severity findings
3. Apply recommended remediation steps
4. Re-scan to verify fixes
5. Close the advisory PR when resolved

## Safety & Legal Considerations

### Authorization Requirements

1. **Written Authorization**: Obtain explicit written permission before scanning any system
2. **Scope Definition**: Clearly define scan scope and timing
3. **Notification**: Inform relevant parties (network admins, security team)
4. **Documentation**: Keep authorization documentation

### Safety Configuration

```json
{
  "safety": {
    "requireConfirmation": true,      // Prompt before scanning
    "authorizedTargetsOnly": true,    // Only scan explicitly authorized targets
    "disableExploits": true,          // Disable exploit modules (scan-only)
    "maxScanDuration": 1800000        // 30-minute timeout
  }
}
```

### Scan Modes (Metasploit)

- **`scan-only`** (Recommended): Auxiliary modules only, no exploits
- **`safe-exploits`**: Non-destructive verification only
- **`full`**: All modules (requires explicit confirmation)

## Troubleshooting

### "Nmap not found"

**Solution**: Install Nmap
```bash
brew install nmap  # macOS
sudo apt-get install nmap  # Linux
```

### "Target not authorized"

**Solution**: Add `"authorized": true` to target configuration
```json
{
  "url": "https://staging.myapp.com",
  "authorized": true
}
```

### "DAST is not configured"

**Solution**: Add DAST section to `.wardenrc.json`
```bash
warden config --create
# Edit .wardenrc.json and add "dast" section
```

### Scan Timeout

**Solution**: Increase timeout or reduce port range
```json
{
  "nmap": {
    "portRange": "1-1000",  // Reduce range
    "timing": 4              // Faster timing
  },
  "safety": {
    "maxScanDuration": 3600000  // 60 minutes
  }
}
```

### Permission Denied (Linux)

Some Nmap scan types require root privileges:

```bash
sudo warden dast https://staging.myapp.com
```

Or use non-privileged scan types:
```json
{
  "nmap": {
    "scanType": "standard",  // Doesn't require root
    "options": ["-sT"]       // TCP connect scan
  }
}
```

## Best Practices

1. **Start with Nmap**: Enable Nmap first, verify results before adding Metasploit
2. **Test Locally**: Scan localhost first to verify configuration
3. **Scheduled Scans**: Run DAST scans regularly (weekly/monthly)
4. **Separate Environments**: Use different targets for dev/staging/production
5. **Document Authorization**: Keep scan authorization documentation
6. **Monitor Scan Impact**: Be aware of network load during scans
7. **Review All Findings**: Don't ignore Low/Medium severity issues

## Example Workflow

### First-Time Setup

```bash
# 1. Install tools
brew install nmap

# 2. Create configuration
warden config --create

# 3. Edit .wardenrc.json, add DAST section (see Configuration above)

# 4. Validate configuration
warden config --validate

# 5. Test with localhost
warden dast http://localhost:3000 --dry-run

# 6. Run actual scan
warden dast http://localhost:3000
```

### Regular Scanning

```bash
# Weekly infrastructure scan
warden dast https://staging.myapp.com

# Review advisory PR
# Apply remediation steps
# Re-scan to verify

warden dast https://staging.myapp.com
```

## Additional Resources

- [Nmap Configuration Guide](./NMAP-CONFIG.md)
- [Metasploit Configuration Guide](./METASPLOIT-CONFIG.md)
- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/hamza-paracha/warden/issues
- Documentation: https://warden-cli.vercel.app

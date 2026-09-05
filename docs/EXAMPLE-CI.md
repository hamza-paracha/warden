# Example GitHub Actions Workflow

Use this workflow in a repository where you want Warden to run on pull requests,
main-branch pushes, a weekly schedule, and manual dispatch.

Create `.github/workflows/warden.yml`:

```yaml
name: Warden Security Patrol

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:

jobs:
  warden:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: 'npm'

      - name: Install project dependencies
        run: |
          if [ -f package-lock.json ]; then
            npm ci
          elif [ -f package.json ]; then
            npm install
          else
            echo "No package.json found; skipping dependency install"
          fi

      - name: Run Warden
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        run: >
          npx @devdonzo/warden scan .
          --ci
          --json
          --scanner npm-audit
          --severity high

      - name: Upload Warden artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: warden-artifacts
          path: |
            scan-results
            SECURITY-ADVISORY.md
```

You can also generate a workflow from the CLI:

```bash
warden bootstrap-ci --scanner npm-audit --severity high
```

For Snyk-backed scans, add `SNYK_TOKEN` in repository secrets and change
`--scanner npm-audit` to `--scanner snyk`.

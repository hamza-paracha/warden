import * as fs from 'fs';
import * as path from 'path';
import { ConfigManager } from './config';

export interface BootstrapCiOptions {
    targetDir?: string;
    workflowName?: string;
    scanner?: 'snyk' | 'npm-audit' | 'pip-audit' | 'all';
    severity?: 'low' | 'medium' | 'high' | 'critical';
    createConfig?: boolean;
    force?: boolean;
}

export interface BootstrapCiResult {
    workflowPath: string;
    configPath?: string;
    created: string[];
    skipped: string[];
}

const DEFAULT_WORKFLOW_NAME = 'warden.yml';

export function bootstrapGitHubActions(options: BootstrapCiOptions = {}): BootstrapCiResult {
    const targetDir = path.resolve(options.targetDir || process.cwd());
    const workflowName = options.workflowName || DEFAULT_WORKFLOW_NAME;
    const workflowDir = path.join(targetDir, '.github', 'workflows');
    const workflowPath = path.join(workflowDir, workflowName);
    const configPath = path.join(targetDir, '.wardenrc.json');
    const created: string[] = [];
    const skipped: string[] = [];

    fs.mkdirSync(workflowDir, { recursive: true });

    if (fs.existsSync(workflowPath) && !options.force) {
        skipped.push(workflowPath);
    } else {
        fs.writeFileSync(
            workflowPath,
            renderGitHubActionsWorkflow({
                scanner: options.scanner || 'npm-audit',
                severity: options.severity || 'high',
            }),
            'utf-8'
        );
        created.push(workflowPath);
    }

    if (options.createConfig) {
        if (fs.existsSync(configPath) && !options.force) {
            skipped.push(configPath);
        } else if (!fs.existsSync(configPath)) {
            ConfigManager.createDefault(configPath);
            created.push(configPath);
        }
    }

    return {
        workflowPath,
        configPath: options.createConfig ? configPath : undefined,
        created,
        skipped,
    };
}

export function renderGitHubActionsWorkflow(options: {
    scanner: 'snyk' | 'npm-audit' | 'pip-audit' | 'all';
    severity: 'low' | 'medium' | 'high' | 'critical';
}): string {
    return `name: Warden Security Patrol

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
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
        run: >
          npx @devdonzo/warden scan .
          --ci
          --json
          --scanner ${options.scanner}
          --severity ${options.severity}

      - name: Upload Warden artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: warden-artifacts
          path: |
            scan-results
            SECURITY-ADVISORY.md
`;
}

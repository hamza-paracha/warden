import { ScanResult, Vulnerability } from './snyk';
import { logger } from '../../utils/logger';
import { runProcess } from '../../services/process';
import { saveScanResult } from '../../services/artifacts';
import { summarizeVulnerabilities } from '../../utils/scan-results';
import * as path from 'path';

const SEVERITY_MAPPING: Record<string, Vulnerability['severity']> = {
    critical: 'critical',
    high: 'high',
    moderate: 'medium',
    medium: 'medium',
    low: 'low',
    info: 'low',
};

export class NpmAuditScanner {
    private readonly projectPath: string;

    constructor(private readonly options: { projectPath?: string; timeoutMs?: number } = {}) {
        this.projectPath = path.resolve(options.projectPath || process.cwd());
    }

    /**
     * Parse severity string to normalized severity level
     */
    parseSeverity(severityStr: string): Vulnerability['severity'] {
        const normalized = (severityStr || 'low').toLowerCase();
        return SEVERITY_MAPPING[normalized] || 'medium';
    }

    /**
     * Format npm audit vulnerabilities object into our standard format
     */
    formatVulnerabilities(data: any): Vulnerability[] {
        const vulnerabilities: Vulnerability[] = [];

        if (!data.vulnerabilities) {
            return vulnerabilities;
        }

        for (const [key, val] of Object.entries(data.vulnerabilities)) {
            const vuln = val as any;
            const severity = this.parseSeverity(vuln.severity);

            vulnerabilities.push({
                id: `NPM-${key}-${vuln.via?.[0]?.source || 'audit'}`,
                title:
                    typeof vuln.via?.[0] === 'object'
                        ? vuln.via[0].title
                        : 'Vulnerability found via npm audit',
                severity,
                packageName: vuln.name || key,
                ecosystem: 'npm',
                version: vuln.range || 'unknown',
                fixedIn: this.extractFixedVersions(vuln.fixAvailable, vuln.name || key),
                description: this.buildDescription(key, vuln),
                cvssScore: undefined,
            });
        }

        return vulnerabilities;
    }

    private extractFixedVersions(fixAvailable: any, packageName: string): string[] {
        if (fixAvailable?.name && fixAvailable.name !== packageName) return [];
        if (!fixAvailable || fixAvailable === true || fixAvailable === false) {
            return [];
        }

        if (typeof fixAvailable.version === 'string' && fixAvailable.version.trim().length > 0) {
            return [fixAvailable.version.trim()];
        }

        return [];
    }

    private buildDescription(packageKey: string, vuln: any): string {
        const directFixVersion = this.extractFixedVersions(
            vuln.fixAvailable,
            vuln.name || packageKey
        )[0];
        const fixHint = directFixVersion
            ? `Direct dependency can be upgraded to ${directFixVersion}.`
            : 'No direct package.json upgrade is available; manual or transitive remediation may be required.';

        return `Dependency path: ${packageKey}. ${fixHint}`;
    }

    async scan(): Promise<ScanResult> {
        logger.watchman('Running npm audit fallback...');

        try {
            const { stdout: jsonOutput, durationMs } = await runProcess(
                'npm',
                ['audit', '--json'],
                {
                    cwd: this.projectPath,
                    timeout: this.options.timeoutMs,
                    allowedExitCodes: [0, 1],
                }
            );
            const result = this.parseAuditOutput(jsonOutput);
            result.metadata = { scanDuration: durationMs, retryCount: 0 };
            saveScanResult(result, this.projectPath);
            return result;
        } catch (error: any) {
            logger.error('npm audit failed', error);
            throw new Error(`npm audit scan failed: ${error.message}`);
        }
    }

    parseAuditOutput(jsonOutput: string): ScanResult {
        let data: any;
        try {
            data = JSON.parse(jsonOutput);
        } catch (e) {
            throw new Error('Failed to parse npm audit JSON output');
        }

        if (
            !data ||
            data.error ||
            !data.vulnerabilities ||
            typeof data.vulnerabilities !== 'object' ||
            Array.isArray(data.vulnerabilities)
        ) {
            throw new Error(
                data?.error?.summary || 'npm audit did not return a vulnerability report'
            );
        }

        const vulnerabilities = this.formatVulnerabilities(data);
        const summary = summarizeVulnerabilities(vulnerabilities);

        const result = {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
            scanner: 'npm-audit',
            projectPath: this.projectPath,
        };

        return result;
    }
}

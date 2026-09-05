import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, Vulnerability } from './snyk';
import { logger } from '../../utils/logger';
import { SCAN_RESULTS_DIR, SCAN_RESULTS_FILE } from '../../constants';

const execAsync = promisify(exec);

const SEVERITY_MAPPING: Record<string, Vulnerability['severity']> = {
    critical: 'critical',
    high: 'high',
    moderate: 'medium',
    medium: 'medium',
    low: 'low',
    info: 'low',
};

export class NpmAuditScanner {
    private outputDir: string;

    constructor() {
        const projectRoot = process.cwd();
        this.outputDir = path.join(projectRoot, SCAN_RESULTS_DIR);

        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
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
                packageName: vuln.name,
                version: vuln.range || 'unknown',
                fixedIn: this.extractFixedVersions(vuln.fixAvailable),
                description: this.buildDescription(key, vuln),
                cvssScore: undefined,
            });
        }

        return vulnerabilities;
    }

    private extractFixedVersions(fixAvailable: any): string[] {
        if (!fixAvailable || fixAvailable === true || fixAvailable === false) {
            return [];
        }

        if (typeof fixAvailable.version === 'string' && fixAvailable.version.trim().length > 0) {
            return [fixAvailable.version.trim()];
        }

        return [];
    }

    private buildDescription(packageKey: string, vuln: any): string {
        const directFixVersion = this.extractFixedVersions(vuln.fixAvailable)[0];
        const fixHint = directFixVersion
            ? `Direct dependency can be upgraded to ${directFixVersion}.`
            : 'No direct package.json upgrade is available; manual or transitive remediation may be required.';

        return `Dependency path: ${packageKey}. ${fixHint}`;
    }

    async scan(): Promise<ScanResult> {
        logger.watchman('Running npm audit fallback...');

        try {
            // npm audit returns exit code 1 if vulnerabilities are found, so we need to handle that
            let jsonOutput = '';
            try {
                const { stdout } = await execAsync('npm audit --json', {
                    maxBuffer: 10 * 1024 * 1024,
                });
                jsonOutput = stdout;
            } catch (error: any) {
                // If the error code is 1, it just means vulns were found, which is fine.
                // If it's something else, then it might be a real error.
                if (error.stdout) {
                    jsonOutput = error.stdout;
                } else {
                    throw error;
                }
            }

            return this.parseAuditOutput(jsonOutput);
        } catch (error: any) {
            logger.error('npm audit failed', error);
            throw new Error(`npm audit scan failed: ${error.message}`);
        }
    }

    private parseAuditOutput(jsonOutput: string): ScanResult {
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
            typeof data.vulnerabilities !== 'object'
        ) {
            throw new Error(
                data?.error?.summary || 'npm audit did not return a vulnerability report'
            );
        }

        const vulnerabilities = this.formatVulnerabilities(data);
        const summary = {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        for (const vuln of vulnerabilities) {
            summary.total++;
            if (Object.hasOwn(summary, vuln.severity)) {
                summary[vuln.severity]++;
            }
        }

        const result = {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
        };

        this.saveScanResults(result);
        return result;
    }

    private saveScanResults(result: ScanResult): void {
        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const filepath = path.join(this.outputDir, `scan-${timestamp}.json`);
        const latestPath = path.join(this.outputDir, SCAN_RESULTS_FILE);
        const content = JSON.stringify(result, null, 2);

        fs.writeFileSync(filepath, content, { encoding: 'utf-8' });
        fs.writeFileSync(latestPath, content, { encoding: 'utf-8' });
    }
}

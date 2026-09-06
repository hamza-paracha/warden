import * as fs from 'fs';
import * as path from 'path';
import { runProcess } from '../../services/process';
import { saveScanResult } from '../../services/artifacts';
import { summarizeVulnerabilities } from '../../utils/scan-results';
import { logger } from '../../utils/logger';
import { ScanResult, Vulnerability } from './snyk';

export class PipAuditScanner {
    private readonly projectPath: string;

    constructor(private readonly options: { projectPath?: string; timeoutMs?: number } = {}) {
        this.projectPath = path.resolve(options.projectPath || process.cwd());
    }

    async scan(): Promise<ScanResult> {
        logger.watchman('Running pip-audit security scan...');

        const requirementsPath = path.resolve(this.projectPath, 'requirements.txt');
        if (!fs.existsSync(requirementsPath)) {
            throw new Error(
                'requirements.txt not found. pip-audit support currently requires requirements.txt'
            );
        }

        const { stdout: jsonOutput, durationMs } = await runProcess(
            'python3',
            ['-m', 'pip_audit', '-r', 'requirements.txt', '--format=json'],
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
    }

    parseAuditOutput(jsonOutput: string): ScanResult {
        let data: any;
        try {
            data = JSON.parse(jsonOutput);
        } catch {
            throw new Error('Failed to parse pip-audit JSON output');
        }

        const vulnerabilities: Vulnerability[] = [];
        if (!data || !Array.isArray(data.dependencies)) {
            throw new Error('pip-audit did not return a dependency report');
        }
        const dependencies = data.dependencies;

        for (const dependency of dependencies) {
            if (!dependency || !Array.isArray(dependency.vulns)) {
                throw new Error('pip-audit returned an incomplete dependency report');
            }
            const vulns = dependency.vulns;
            for (const vuln of vulns) {
                const fixVersions = Array.isArray(vuln.fix_versions) ? vuln.fix_versions : [];
                const aliases = Array.isArray(vuln.aliases) ? vuln.aliases : [];
                vulnerabilities.push({
                    id: vuln.id || aliases[0] || `PYSEC-${dependency.name}`,
                    title: vuln.description || `Vulnerability in ${dependency.name}`,
                    severity: this.inferSeverity(vuln),
                    packageName: dependency.name,
                    version: dependency.version,
                    fixedIn: fixVersions,
                    description: vuln.description || `Known vulnerability in ${dependency.name}`,
                    references: aliases,
                    ecosystem: 'python',
                });
            }
        }

        const summary = summarizeVulnerabilities(vulnerabilities);

        return {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
            scanner: 'pip-audit',
            projectPath: this.projectPath,
        };
    }

    private inferSeverity(vuln: any): Vulnerability['severity'] {
        // Descriptions are not severity data (e.g. "overflow" contains "low").
        const severity = String(vuln.severity || '').toLowerCase();
        if (severity === 'critical' || severity === 'high' || severity === 'low') return severity;
        return 'medium';
    }
}

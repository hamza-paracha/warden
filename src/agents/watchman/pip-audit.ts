import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from '../../utils/logger';
import { SCAN_RESULTS_DIR, SCAN_RESULTS_FILE } from '../../constants';
import { ScanResult, Vulnerability } from './snyk';

const execAsync = promisify(exec);

export class PipAuditScanner {
    private outputDir: string;

    constructor() {
        const projectRoot = process.cwd();
        this.outputDir = path.join(projectRoot, SCAN_RESULTS_DIR);

        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }

    async scan(): Promise<ScanResult> {
        logger.watchman('Running pip-audit security scan...');

        const requirementsPath = path.resolve(process.cwd(), 'requirements.txt');
        if (!fs.existsSync(requirementsPath)) {
            throw new Error(
                'requirements.txt not found. pip-audit support currently requires requirements.txt'
            );
        }

        try {
            await execAsync('python3 -m pip_audit --version', { maxBuffer: 1024 * 1024 });
        } catch {
            throw new Error(
                'pip-audit is not installed. Install with: python3 -m pip install pip-audit'
            );
        }

        let jsonOutput = '';
        try {
            const { stdout } = await execAsync(
                'python3 -m pip_audit -r requirements.txt --format=json',
                { maxBuffer: 10 * 1024 * 1024, cwd: process.cwd() }
            );
            jsonOutput = stdout;
        } catch (error: any) {
            if (error.stdout) {
                jsonOutput = error.stdout;
            } else {
                throw error;
            }
        }

        const result = this.parseAuditOutput(jsonOutput);
        this.saveScanResults(result);
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
        const dependencies = Array.isArray(data.dependencies) ? data.dependencies : [];

        for (const dependency of dependencies) {
            const vulns = Array.isArray(dependency.vulns) ? dependency.vulns : [];
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

        const summary = {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter(
                (vulnerability) => vulnerability.severity === 'critical'
            ).length,
            high: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'high')
                .length,
            medium: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'medium')
                .length,
            low: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'low').length,
        };

        return {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
            scanner: 'pip-audit',
        };
    }

    private inferSeverity(vuln: any): Vulnerability['severity'] {
        const aliases = Array.isArray(vuln.aliases) ? vuln.aliases.join(' ') : '';
        const description = `${vuln.description || ''} ${aliases}`.toLowerCase();

        if (description.includes('critical')) return 'critical';
        if (description.includes('high')) return 'high';
        if (description.includes('low')) return 'low';
        return 'medium';
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

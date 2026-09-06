import * as fs from 'fs';
import * as path from 'path';

import { NpmFixer, PipFixer } from './fixer';
import { logger } from '../../utils/logger';
import { Vulnerability, Diagnosis, FixInstruction, ScanMode } from '../../types';
import { SEVERITY_PRIORITY, DEFAULT_BRANCH_PREFIX } from '../../constants';

export type { Diagnosis };

// ─── Local scan-result shape ──────────────────────────────────────────────────
// Kept intentionally loose to accept files produced by all scanners
// (SnykScanner, NpmAuditScanner, MockScanner, DAST scanners).
interface ScanResults {
    timestamp: string;
    vulnerabilities: Vulnerability[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    scanMode?: ScanMode;
    scanner?: string;
}

// ─────────────────────────────────────────────────────────────────────────────

export class EngineerAgent {
    private fixers: Array<NpmFixer | PipFixer>;

    constructor() {
        this.fixers = [new NpmFixer(), new PipFixer()];
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    private async readScanResults(scanResultsPath: string): Promise<ScanResults> {
        logger.engineer(`Reading scan results from ${scanResultsPath}...`);

        const absolutePath = path.isAbsolute(scanResultsPath)
            ? scanResultsPath
            : path.resolve(process.cwd(), scanResultsPath);

        if (!fs.existsSync(absolutePath)) {
            throw new Error(`Scan results file not found: ${absolutePath}`);
        }

        const fileContent = fs.readFileSync(absolutePath, 'utf-8');
        return JSON.parse(fileContent) as ScanResults;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private prioritizeVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
        return [...vulnerabilities].sort((a, b) => {
            const priorityDiff =
                (SEVERITY_PRIORITY[b.severity] ?? 0) - (SEVERITY_PRIORITY[a.severity] ?? 0);
            if (priorityDiff !== 0) return priorityDiff;
            return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
        });
    }

    canAttemptFix(vuln: Vulnerability): boolean {
        return Array.isArray(vuln.fixedIn) && vuln.fixedIn.length > 0;
    }

    getFixVersion(vuln: Vulnerability): string | null {
        if (!vuln.fixedIn || vuln.fixedIn.length === 0) return null;
        return vuln.fixedIn[vuln.fixedIn.length - 1];
    }

    // ── SAST ──────────────────────────────────────────────────────────────────

    /**
     * Analyse scan results and produce a prioritised list of Diagnoses.
     *
     * Each SAST diagnosis now carries a structured `fixInstruction` so that
     * `applyFix` never needs to parse a human-readable string via regex.
     */
    async diagnose(scanResultsPath: string | ScanResults): Promise<Diagnosis[]> {
        logger.engineer('Analyzing scan results...');

        const scanResults =
            typeof scanResultsPath === 'string'
                ? await this.readScanResults(scanResultsPath)
                : scanResultsPath;

        if (scanResults.scanMode === 'dast') {
            logger.info('DAST scan detected — generating advisory recommendations');
            return this.generateDastAdvisories(scanResults);
        }

        const prioritized = this.prioritizeVulnerabilities(scanResults.vulnerabilities);
        logger.info(`Found ${scanResults.summary.total} vulnerabilities`);

        return prioritized.map((vuln): Diagnosis => {
            const targetVersion = this.getFixVersion(vuln);

            // Build structured fix instruction when the data is available
            const fixInstruction: FixInstruction | undefined =
                targetVersion && vuln.packageName && vuln.version
                    ? {
                          ecosystem: vuln.ecosystem || 'npm',
                          packageName: vuln.packageName,
                          currentVersion: vuln.version,
                          targetVersion,
                          manifestPath:
                              vuln.ecosystem === 'python' ? 'requirements.txt' : 'package.json',
                      }
                    : undefined;

            return {
                vulnerabilityId: vuln.id,
                packageName: vuln.packageName,
                description: `${vuln.title} in ${vuln.packageName}@${vuln.version} (${vuln.severity.toUpperCase()})`,
                // Human-readable string kept for display / logging purposes
                suggestedFix: targetVersion
                    ? `Update ${vuln.packageName} from ${vuln.version} to ${targetVersion}`
                    : `No known fix for ${vuln.packageName}@${vuln.version}`,
                filesToModify: targetVersion
                    ? [vuln.ecosystem === 'python' ? 'requirements.txt' : 'package.json']
                    : [],
                fixInstruction,
            };
        });
    }

    // ── DAST advisories ───────────────────────────────────────────────────────

    private generateDastAdvisories(scanResults: ScanResults): Diagnosis[] {
        logger.info(`Found ${scanResults.summary.total} DAST findings`);
        const prioritized = this.prioritizeVulnerabilities(scanResults.vulnerabilities);

        return prioritized.map(
            (vuln): Diagnosis => ({
                vulnerabilityId: vuln.id,
                packageName: vuln.packageName,
                description: this.formatDastFinding(vuln),
                suggestedFix: this.generateDastRemediation(vuln),
                filesToModify: [],
                // No fixInstruction for DAST — manual remediation required
            })
        );
    }

    private formatDastFinding(vuln: Vulnerability): string {
        let description = `${vuln.title} (${vuln.severity.toUpperCase()})`;

        if (vuln.targetHost) description += `\nHost: ${vuln.targetHost}`;
        if (vuln.targetPort) description += `\nPort: ${vuln.targetPort}`;
        if (vuln.service) {
            description += `\nService: ${vuln.service}`;
            if (vuln.serviceVersion) description += ` (${vuln.serviceVersion})`;
        }

        description += `\n\n${vuln.description}`;

        if (vuln.findings && vuln.findings.length > 0) {
            description += '\n\nTechnical Details:';
            vuln.findings.forEach((f) => (description += `\n  - ${f}`));
        }

        return description;
    }

    private generateDastRemediation(vuln: Vulnerability): string {
        const steps: string[] = ['**Manual Remediation Required**', ''];

        if (vuln.targetPort) {
            const port = vuln.targetPort;

            if ([3306, 5432, 27017, 6379, 9200, 9300].includes(port)) {
                steps.push('1. Verify database exposure is intentional');
                steps.push('2. Implement firewall rules to restrict access to trusted IPs');
                steps.push('3. Enable authentication with strong passwords');
                steps.push('4. Use VPN or SSH tunneling for remote access');
                steps.push('5. Update to latest patch version');
            } else if ([21, 23].includes(port)) {
                steps.push('**CRITICAL: Disable this insecure protocol immediately**');
                steps.push('1. Stop the service');
                steps.push('2. Replace with secure alternative (SSH/SFTP)');
                steps.push('3. If required, restrict to internal network only');
            } else if ([80, 443, 8080, 8443].includes(port)) {
                steps.push('1. Ensure HTTPS is enabled with valid TLS certificate');
                steps.push('2. Configure security headers (HSTS, CSP, X-Frame-Options)');
                steps.push('3. Keep web server software up to date');
                steps.push('4. Review application security controls');
            } else {
                steps.push('1. Review if this port needs to be exposed');
                steps.push('2. Implement network segmentation');
                steps.push('3. Use firewall rules to restrict access');
                steps.push('4. Update service to latest version');
            }
        }

        if (vuln.service?.toLowerCase().includes('ssh')) {
            steps.push('', '**SSH Hardening:**');
            steps.push('- Disable password authentication');
            steps.push('- Use SSH keys only');
            steps.push('- Implement fail2ban for brute-force protection');
        }

        if (vuln.exploitAvailable) {
            steps.push('', '⚠️  **EXPLOIT AVAILABLE** - Prioritize remediation');
            if (vuln.exploitModule) steps.push(`Module: ${vuln.exploitModule}`);
        }

        return steps.join('\n');
    }

    // ── Fix application ───────────────────────────────────────────────────────

    /**
     * Apply the fix described by `diagnosis`.
     *
     * Primary path: use the structured `fixInstruction` field with `NpmFixer`.
     * Fallback path: parse the `suggestedFix` string (legacy / backward compat).
     */
    async applyFix(diagnosis: Diagnosis): Promise<boolean> {
        logger.engineer(`Applying fix for ${diagnosis.vulnerabilityId}...`);

        // ── Structured path (preferred) ────────────────────────────────────
        if (diagnosis.fixInstruction) {
            const { fixInstruction } = diagnosis;
            const fixer = this.fixers.find((candidate) => candidate.canFix(fixInstruction));

            if (!fixer) {
                logger.error(
                    `No fixer can handle "${fixInstruction.packageName}". ` +
                        'This may be a transitive dependency or unsupported manifest type.'
                );
                return false;
            }

            return fixer.applyFix(fixInstruction, diagnosis.vulnerabilityId, DEFAULT_BRANCH_PREFIX);
        }

        // ── Legacy regex fallback ──────────────────────────────────────────
        logger.warn('No structured fixInstruction found; falling back to regex parsing.');

        const match = diagnosis.suggestedFix.match(
            /Update\s+([^\s]+)\s+from\s+([^\s]+)\s+to\s+([^\s]+)/
        );

        if (!match) {
            logger.error('Could not parse fix suggestion format.');
            return false;
        }

        const [, packageName, currentVersion, newVersion] = match;

        const fallbackInstruction: FixInstruction = {
            ecosystem: 'npm',
            packageName,
            currentVersion,
            targetVersion: newVersion,
            manifestPath: 'package.json',
        };
        const fixer = this.fixers[0];

        return fixer.applyFix(
            fallbackInstruction,
            diagnosis.vulnerabilityId,
            DEFAULT_BRANCH_PREFIX
        );
    }

    // ── Main run ──────────────────────────────────────────────────────────────

    async run(scanResultsPath: string): Promise<void> {
        logger.engineer('Engineer Agent Starting...');

        try {
            const diagnoses = await this.diagnose(scanResultsPath);

            if (diagnoses.length === 0) {
                logger.info('No vulnerabilities found.');
                return;
            }

            const criticalDiagnosis = diagnoses[0];
            logger.info(
                `Targeting highest priority vulnerability: ${criticalDiagnosis.vulnerabilityId}`
            );

            const success = await this.applyFix(criticalDiagnosis);

            if (success) {
                logger.success('Engineer Agent completed successfully!');
            } else {
                logger.warn('Engineer Agent failed to fix the issue.');
            }
        } catch (error: any) {
            logger.error('Engineer Agent encountered an error:', error);
            throw error;
        }
    }
}

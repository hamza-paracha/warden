import * as path from 'path';
import { logger } from '../../utils/logger';
import { runProcess } from '../../services/process';
import { saveScanResult } from '../../services/artifacts';
import { summarizeVulnerabilities } from '../../utils/scan-results';

import type {
    ScannerVulnerability as Vulnerability,
    ScannerResult as ScanResult,
} from '../../scanners';
export type {
    ScannerVulnerability as Vulnerability,
    ScannerResult as ScanResult,
} from '../../scanners';

export interface ScannerOptions {
    token?: string;
    projectPath?: string;
    maxRetries?: number;
    retryDelayMs?: number;
    timeoutMs?: number;
}

export class SnykScanner {
    private readonly projectPath: string;
    private readonly maxRetries: number;
    private readonly retryDelayMs: number;
    private readonly timeoutMs: number;
    private readonly token?: string;

    constructor(options: ScannerOptions = {}) {
        this.projectPath = path.resolve(options.projectPath || process.cwd());
        this.maxRetries = options.maxRetries ?? 3;
        this.retryDelayMs = options.retryDelayMs ?? 2000;
        this.timeoutMs = options.timeoutMs ?? 300000;
        this.token = options.token;
    }

    private async retryWithBackoff<T>(
        fn: () => Promise<T>,
        operationName: string,
        attempt = 1
    ): Promise<T> {
        try {
            return await fn();
        } catch (error: any) {
            const isTimeout =
                error.code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' &&
                (error.killed || error.signal === 'SIGTERM');
            const isNetworkError = error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED';

            if (attempt < this.maxRetries && (isTimeout || isNetworkError)) {
                const delay = this.retryDelayMs * Math.pow(2, attempt - 1);
                logger.warn(
                    `${operationName} failed (attempt ${attempt}/${this.maxRetries}). ` +
                        `Retrying in ${delay}ms... Reason: ${error.message}`
                );

                await new Promise((resolve) => setTimeout(resolve, delay));
                return this.retryWithBackoff(fn, operationName, attempt + 1);
            }

            throw error;
        }
    }

    async test(): Promise<ScanResult> {
        logger.watchman('Running Snyk security scan...');
        const startTime = Date.now();
        let retryCount = 0;
        const errors: string[] = [];

        try {
            const result = await this.retryWithBackoff(async () => {
                retryCount++;
                const { stdout } = await runProcess('snyk', ['test', '--json'], {
                    cwd: this.projectPath,
                    timeout: this.timeoutMs,
                    allowedExitCodes: [0, 1],
                    ...(this.token ? { env: { ...process.env, SNYK_TOKEN: this.token } } : {}),
                });
                return stdout;
            }, 'Snyk security scan');

            const scanDuration = Date.now() - startTime;
            const scanResult = this.parseSnykOutput(result);

            scanResult.metadata = {
                scanDuration,
                retryCount: retryCount - 1,
                errors: errors.length > 0 ? errors : undefined,
            };

            saveScanResult(scanResult, this.projectPath);
            logger.success(`Scan completed in ${(scanDuration / 1000).toFixed(2)}s`);
            return scanResult;
        } catch (error: any) {
            const errorMsg = `Snyk scan failed: ${error.message}`;
            errors.push(errorMsg);
            throw new Error(errorMsg);
        }
    }

    parseSnykOutput(jsonOutput: string): ScanResult {
        logger.watchman('Parsing Snyk results...');
        let data: any;
        try {
            data = JSON.parse(jsonOutput);
        } catch {
            throw new Error('Failed to parse Snyk JSON output');
        }

        const reports = Array.isArray(data) ? data : [data];
        if (
            reports.length === 0 ||
            reports.some(
                (report) => !report || report.error || !Array.isArray(report.vulnerabilities)
            )
        ) {
            throw new Error('Snyk did not return a vulnerability report');
        }
        const vulnerabilities: Vulnerability[] = [];
        for (const report of reports) {
            for (const vuln of report.vulnerabilities) {
                const rawSeverity = String(vuln.severity || 'medium').toLowerCase();
                const severity: Vulnerability['severity'] =
                    rawSeverity === 'critical' || rawSeverity === 'high' || rawSeverity === 'low'
                        ? rawSeverity
                        : 'medium';
                vulnerabilities.push({
                    id: vuln.id || vuln.CVSSv3 || 'unknown',
                    title: vuln.title || 'Unknown vulnerability',
                    severity,
                    packageName: vuln.packageName || vuln.name || 'unknown',
                    version: vuln.version || 'unknown',
                    fixedIn: Array.isArray(vuln.fixedIn) ? vuln.fixedIn : [],
                    description: vuln.description || '',
                    cvssScore: vuln.cvssScore,
                    ecosystem: report.packageManager === 'pip' ? 'python' : 'npm',
                });
            }
        }
        const summary = summarizeVulnerabilities(vulnerabilities);

        const result: ScanResult = {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
            scanner: 'snyk',
            projectPath: this.projectPath,
        };
        return result;
    }

    filterHighPriority(result: ScanResult): Vulnerability[] {
        return result.vulnerabilities.filter(
            (v) => v.severity === 'critical' || v.severity === 'high'
        );
    }

    printSummary(result: ScanResult): void {
        logger.header('SECURITY SCAN SUMMARY');
        logger.info(`Timestamp: ${result.timestamp}`);
        logger.info(`Total Vulnerabilities: ${result.summary.total}`);
        logger.info(`  Critical: ${result.summary.critical}`);
        logger.info(`  High: ${result.summary.high}`);
        logger.info(`  Medium: ${result.summary.medium}`);
        logger.info(`  Low: ${result.summary.low}`);

        const highPriority = this.filterHighPriority(result);
        if (highPriority.length > 0) {
            logger.warn('HIGH PRIORITY VULNERABILITIES:');
            highPriority.forEach((v, i) => {
                logger.warn(`${i + 1}. [${v.severity.toUpperCase()}] ${v.title}`);
                logger.info(`   Package: ${v.packageName}@${v.version}`);
                logger.info(`   ID: ${v.id}`);
            });
        }
    }
}

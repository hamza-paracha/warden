import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger';

const execAsync = promisify(exec);

export interface Vulnerability {
    id: string;
    title: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    packageName: string;
    version: string;
    fixedIn?: string[];
    description?: string;
    cvssScore?: number;
    references?: string[];
    ecosystem?: 'npm' | 'python';
}

export interface ScanResult {
    timestamp: string;
    vulnerabilities: Vulnerability[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    scanner?: string;
    projectPath?: string;
    scanMode?: string;
    metadata?: {
        scanDuration?: number;
        retryCount?: number;
        errors?: string[];
        [key: string]: any;
    };
}

export interface ScannerOptions {
    token?: string;
    maxRetries?: number;
    retryDelayMs?: number;
    timeoutMs?: number;
}

export class SnykScanner {
    private outputDir: string;
    private maxRetries: number;
    private retryDelayMs: number;
    private timeoutMs: number;

    constructor(options: ScannerOptions = {}) {
        const { token, maxRetries = 3, retryDelayMs = 2000, timeoutMs = 300000 } = options;

        if (!process.env.SNYK_TOKEN && !token) {
            logger.warn('SNYK_TOKEN not found. Scanner may fail or require CLI login.');
        }

        this.maxRetries = maxRetries;
        this.retryDelayMs = retryDelayMs;
        this.timeoutMs = timeoutMs;

        // Store results alongside the project being scanned.
        this.outputDir = path.resolve(process.cwd(), 'scan-results');

        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }

    private async retryWithBackoff<T>(
        fn: () => Promise<T>,
        operationName: string,
        attempt = 1
    ): Promise<T> {
        try {
            return await fn();
        } catch (error: any) {
            const isTimeout = error.killed || error.signal === 'SIGTERM';
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
            await this.retryWithBackoff(async () => {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 10000);
                try {
                    await execAsync('snyk --version', {
                        signal: controller.signal as any,
                    });
                } finally {
                    clearTimeout(timeout);
                }
            }, 'Snyk CLI version check');
        } catch (error: any) {
            const errorMsg =
                'Snyk CLI not found or not responding. Please install: npm install -g snyk';
            errors.push(errorMsg);
            throw new Error(errorMsg);
        }

        try {
            const result = await this.retryWithBackoff(async () => {
                logger.watchman(`Executing Snyk scan (timeout: ${this.timeoutMs / 1000}s)...`);
                try {
                    const { stdout } = await execAsync('snyk test --json', {
                        maxBuffer: 10 * 1024 * 1024,
                        timeout: this.timeoutMs,
                        cwd: process.cwd(), // Scan the current directory
                    });
                    return stdout;
                } catch (error: any) {
                    if (error.stdout) return error.stdout;
                    if (error.killed || error.signal === 'SIGTERM') {
                        throw new Error(`Snyk scan timed out after ${this.timeoutMs / 1000}s`);
                    }
                    throw error;
                }
            }, 'Snyk security scan');

            const scanDuration = Date.now() - startTime;
            const scanResult = this.parseSnykOutput(result);

            scanResult.metadata = {
                scanDuration,
                retryCount,
                errors: errors.length > 0 ? errors : undefined,
            };

            logger.success(`Scan completed in ${(scanDuration / 1000).toFixed(2)}s`);
            return scanResult;
        } catch (error: any) {
            const errorMsg = `Snyk scan failed: ${error.message}`;
            errors.push(errorMsg);
            const fallbackResult: ScanResult = {
                timestamp: new Date().toISOString(),
                vulnerabilities: [],
                summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                metadata: { scanDuration: Date.now() - startTime, retryCount, errors },
            };
            this.saveScanResults(fallbackResult);
            throw new Error(errorMsg);
        }
    }

    private parseSnykOutput(jsonOutput: string): ScanResult {
        logger.watchman('Parsing Snyk results...');
        let data: any;
        try {
            data = JSON.parse(jsonOutput);
        } catch {
            throw new Error('Failed to parse Snyk JSON output');
        }

        const vulnerabilities: Vulnerability[] = [];
        const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };

        if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
            for (const vuln of data.vulnerabilities) {
                const severity = (
                    vuln.severity || 'low'
                ).toLowerCase() as Vulnerability['severity'];
                vulnerabilities.push({
                    id: vuln.id || vuln.CVSSv3 || 'unknown',
                    title: vuln.title || 'Unknown vulnerability',
                    severity,
                    packageName: vuln.packageName || vuln.name || 'unknown',
                    version: vuln.version || 'unknown',
                    fixedIn: vuln.fixedIn || [],
                    description: vuln.description,
                    cvssScore: vuln.cvssScore,
                });
                summary.total++;
                summary[severity]++;
            }
        }

        const result: ScanResult = {
            timestamp: new Date().toISOString(),
            vulnerabilities,
            summary,
        };
        this.saveScanResults(result);
        return result;
    }

    private saveScanResults(result: ScanResult): void {
        try {
            this.validateScanResult(result);
            const timestamp = new Date().toISOString().replace(/:/g, '-');
            const filename = `scan-${timestamp}.json`;
            const filepath = path.join(this.outputDir, filename);
            const latestPath = path.join(this.outputDir, 'scan-results.json');
            const jsonContent = JSON.stringify(result, null, 2);

            const tempPath = `${filepath}.tmp`;
            const tempLatestPath = `${latestPath}.tmp`;

            try {
                fs.writeFileSync(tempPath, jsonContent, { encoding: 'utf8' });
                fs.renameSync(tempPath, filepath);
                fs.writeFileSync(tempLatestPath, jsonContent, { encoding: 'utf8' });
                fs.renameSync(tempLatestPath, latestPath);
                logger.info(`Scan results saved to: ${filepath}`);
                logger.debug(`Latest results: ${latestPath}`);
            } catch (writeError) {
                [tempPath, tempLatestPath].forEach((tmpFile) => {
                    if (fs.existsSync(tmpFile))
                        try {
                            fs.unlinkSync(tmpFile);
                        } catch {
                            /* ignore */
                        }
                });
                throw writeError;
            }
        } catch (error: any) {
            logger.error(`Failed to save scan results: ${error.message}`);
            throw error;
        }
    }

    private validateScanResult(result: ScanResult): void {
        if (!result) throw new Error('Scan result is null or undefined');
        if (!result.timestamp || typeof result.timestamp !== 'string')
            throw new Error('Invalid timestamp');
        if (!Array.isArray(result.vulnerabilities))
            throw new Error('Vulnerabilities must be an array');
        if (!result.summary || typeof result.summary !== 'object')
            throw new Error('Invalid summary');
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

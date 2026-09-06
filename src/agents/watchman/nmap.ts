/**
 * Nmap Scanner for Warden DAST
 *
 * Network discovery and security auditing using Nmap
 */

import { runProcess } from '../../services/process';
import { promises as fs } from 'fs';
import * as path from 'path';
import { parseStringPromise } from 'xml2js';
import { logger } from '../../utils/logger';
import { Vulnerability, ScanResult, NmapConfig, DastTarget } from '../../types';

export class NmapScanner {
    private config: NmapConfig;
    private target: DastTarget;
    private outputDir: string;

    constructor(config: NmapConfig, target: DastTarget, outputDir: string = 'scan-results/dast') {
        this.config = config;
        this.target = target;
        this.outputDir = outputDir;
    }

    /**
     * Check if Nmap is installed and get version
     */
    async checkInstallation(): Promise<{ installed: boolean; version?: string }> {
        try {
            const { stdout } = await runProcess('nmap', ['--version'], { timeout: 10000 });
            const versionMatch = stdout.match(/Nmap version ([0-9.]+)/);
            const version = versionMatch ? versionMatch[1] : 'unknown';
            logger.info(`Nmap detected: version ${version}`);
            return { installed: true, version };
        } catch (error) {
            logger.error('Nmap not found. Please install nmap to use DAST features.');
            return { installed: false };
        }
    }

    /**
     * Build nmap command based on scan type and configuration
     */
    private buildNmapArgs(xmlOutputPath: string): string[] {
        const url = new URL(this.target.url);
        const targetHost = url.hostname;

        const baseCmd: string[] = [];

        // Add scan type specific flags
        switch (this.config.scanType) {
            case 'quick':
                baseCmd.push('-T4', '-F'); // Fast scan, top 100 ports
                break;
            case 'standard':
                baseCmd.push('-T3', '-sV'); // Version detection
                break;
            case 'comprehensive':
                baseCmd.push('-T3', '-sV', '-sC', '-A'); // Aggressive scan
                break;
            case 'stealth':
                baseCmd.push('-T2', '-sS', '-Pn'); // Stealth SYN scan
                break;
        }

        // Add timing template if specified
        if (this.config.timing !== undefined) {
            baseCmd.push(`-T${this.config.timing}`);
        }

        // Add port range
        const portRange = this.target.ports || this.config.portRange || '1-1000';
        baseCmd.push('-p', portRange);

        // Add custom options
        if (this.config.options && this.config.options.length > 0) {
            baseCmd.push(...this.config.options);
        }

        // Add XML output
        baseCmd.push('-oX', xmlOutputPath);

        // Add target
        baseCmd.push(targetHost);

        return baseCmd;
    }

    /**
     * Execute Nmap scan
     */
    async scan(): Promise<ScanResult> {
        const startTime = Date.now();

        // Check authorization
        if (!this.target.authorized) {
            throw new Error(
                `Target ${this.target.url} is not authorized for scanning. Set "authorized: true" in configuration.`
            );
        }

        // Check Nmap installation
        const { installed, version } = await this.checkInstallation();
        if (!installed) {
            throw new Error('Nmap is not installed. Please install Nmap to continue.');
        }

        // Create output directory
        await fs.mkdir(this.outputDir, { recursive: true });

        // Generate output filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const xmlOutputPath = path.join(this.outputDir, `nmap-${timestamp}.xml`);

        // Build and execute command
        const args = this.buildNmapArgs(xmlOutputPath);
        logger.info(`Executing Nmap scan for ${this.target.url}`);

        try {
            const { stderr } = await runProcess('nmap', args, {
                maxBuffer: 10 * 1024 * 1024, // 10MB buffer
            });

            if (stderr && !stderr.includes('Warning')) {
                logger.warn(`Nmap stderr: ${stderr}`);
            }

            // Parse XML output
            const xmlContent = await fs.readFile(xmlOutputPath, 'utf-8');
            const vulnerabilities = await this.parseNmapXML(xmlContent);

            const duration = Date.now() - startTime;

            const result: ScanResult = {
                timestamp: new Date().toISOString(),
                vulnerabilities,
                summary: this.calculateSummary(vulnerabilities),
                scanner: 'nmap',
                projectPath: this.target.url,
                scanMode: 'dast',
                scanMetadata: {
                    target: this.target.url,
                    scanType: this.config.scanType,
                    duration,
                    nmapVersion: version,
                    outputFile: xmlOutputPath,
                },
            };

            logger.info(
                `Nmap scan completed. Found ${vulnerabilities.length} findings in ${duration}ms`
            );
            return result;
        } catch (error) {
            logger.error(`Nmap scan failed: ${error}`);
            throw error;
        }
    }

    /**
     * Parse Nmap XML output and convert to vulnerabilities
     */
    private async parseNmapXML(xmlContent: string): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];

        try {
            const parsed = await parseStringPromise(xmlContent);
            const nmaprun = parsed.nmaprun;

            if (!nmaprun || !nmaprun.host) {
                logger.warn('No hosts found in Nmap scan results');
                return vulnerabilities;
            }

            const hosts = Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host];

            for (const host of hosts) {
                const address = host.address?.[0]?.$?.addr || 'unknown';
                const ports = host.ports?.[0]?.port;

                if (!ports) continue;

                const portList = Array.isArray(ports) ? ports : [ports];

                for (const port of portList) {
                    const portId = port.$?.portid;
                    const protocol = port.$?.protocol || 'tcp';
                    const state = port.state?.[0]?.$?.state;
                    const service = port.service?.[0];

                    if (state === 'open') {
                        const serviceName = service?.$?.name || 'unknown';
                        const serviceVersion =
                            service?.$?.version || service?.$?.product || 'unknown';
                        const extraInfo = service?.$?.extrainfo || '';

                        // Determine severity based on port and service
                        const severity = this.determineSeverity(parseInt(portId), serviceName);

                        // Check for risky services
                        const isRisky = this.isRiskyPort(parseInt(portId), serviceName);

                        vulnerabilities.push({
                            id: `nmap-${address}-${portId}-${protocol}`,
                            title: `Open ${protocol.toUpperCase()} port ${portId} - ${serviceName}`,
                            severity,
                            packageName: serviceName,
                            version: serviceVersion,
                            fixedIn: [],
                            description: this.generateDescription(
                                portId,
                                serviceName,
                                serviceVersion,
                                extraInfo,
                                isRisky
                            ),
                            targetHost: address,
                            targetPort: parseInt(portId),
                            service: serviceName,
                            serviceVersion,
                            exploitAvailable: false,
                            findings: this.extractNseScriptResults(port),
                        });
                    }
                }
            }
        } catch (error) {
            logger.error(`Failed to parse Nmap XML: ${error}`);
            throw error;
        }

        return vulnerabilities;
    }

    /**
     * Extract NSE script results from port data
     */
    private extractNseScriptResults(port: any): string[] {
        const findings: string[] = [];

        if (port.script) {
            const scripts = Array.isArray(port.script) ? port.script : [port.script];
            for (const script of scripts) {
                const scriptId = script.$?.id;
                const output = script.$?.output;
                if (scriptId && output) {
                    findings.push(`${scriptId}: ${output}`);
                }
            }
        }

        return findings;
    }

    /**
     * Determine severity based on port number and service
     */
    private determineSeverity(
        port: number,
        service: string
    ): 'critical' | 'high' | 'medium' | 'low' {
        // Critical: Database ports, remote admin
        const criticalPorts = [1433, 3306, 5432, 5984, 6379, 27017, 27018, 9200, 9300];
        const criticalServices = [
            'mysql',
            'postgresql',
            'mongodb',
            'redis',
            'couchdb',
            'elasticsearch',
        ];

        if (criticalPorts.includes(port) || criticalServices.includes(service.toLowerCase())) {
            return 'critical';
        }

        // High: Telnet, FTP, unencrypted protocols
        const highRiskPorts = [21, 23, 25, 69, 111, 161, 512, 513, 514];
        const highRiskServices = ['telnet', 'ftp', 'tftp', 'rexec', 'rlogin', 'rsh', 'snmp'];

        if (highRiskPorts.includes(port) || highRiskServices.includes(service.toLowerCase())) {
            return 'high';
        }

        // Medium: Common services
        const mediumPorts = [80, 443, 8080, 8443, 3000, 5000];
        if (mediumPorts.includes(port)) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Check if port/service is considered risky
     */
    private isRiskyPort(port: number, service: string): boolean {
        const riskyPorts = [21, 23, 25, 69, 111, 161, 512, 513, 514, 1433, 3306, 5432, 6379, 27017];
        const riskyServices = ['telnet', 'ftp', 'tftp', 'mysql', 'postgresql', 'mongodb', 'redis'];

        return riskyPorts.includes(port) || riskyServices.includes(service.toLowerCase());
    }

    /**
     * Generate human-readable description
     */
    private generateDescription(
        port: string,
        service: string,
        version: string,
        extraInfo: string,
        isRisky: boolean
    ): string {
        let description = `Port ${port} is open and running ${service}`;

        if (version && version !== 'unknown') {
            description += ` (version: ${version})`;
        }

        if (extraInfo) {
            description += `. Additional info: ${extraInfo}`;
        }

        if (isRisky) {
            description +=
                '\n\n⚠️  This is a high-risk service that should typically not be exposed to the internet.';
        }

        return description;
    }

    /**
     * Calculate vulnerability summary
     */
    private calculateSummary(vulnerabilities: Vulnerability[]) {
        return {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
            high: vulnerabilities.filter((v) => v.severity === 'high').length,
            medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
            low: vulnerabilities.filter((v) => v.severity === 'low').length,
        };
    }
}

/**
 * Scanner Plugin System
 *
 * Defines the IScanner interface and ScannerRegistry for the Warden scanner
 * plugin architecture. Any scanner (Snyk, npm-audit, mock, etc.) can be
 * registered with the registry and used interchangeably.
 */

import { logger } from '../utils/logger';
import { Vulnerability, ScanSummary } from '../types';

/**
 * The canonical scan result shape used across all scanners.
 * Must match the structure produced by SnykScanner and NpmAuditScanner.
 */
export interface ScannerVulnerability extends Omit<Vulnerability, 'fixedIn' | 'description'> {
    fixedIn?: string[];
    description?: string;
}

export interface ScannerResult {
    timestamp: string;
    vulnerabilities: ScannerVulnerability[];
    summary: ScanSummary;
    scanner?: string;
    projectPath?: string;
    scanMode?: string;
    metadata?: Record<string, any>;
}

/**
 * Interface that every scanner plugin must implement.
 */
export interface IScanner {
    /** Unique, human-readable name for this scanner (e.g. 'snyk', 'npm-audit', 'mock') */
    readonly name: string;
    /** Execute the scan and return structured results */
    scan(): Promise<ScannerResult>;
}

/**
 * Registry that holds scanner plugins and provides a fallback scan chain.
 */
export class ScannerRegistry {
    private scanners: Map<string, IScanner> = new Map();

    /**
     * Register a scanner. If a scanner with the same name is already registered
     * it will be overwritten.
     */
    register(scanner: IScanner): void {
        logger.debug(`[ScannerRegistry] Registering scanner: ${scanner.name}`);
        this.scanners.set(scanner.name, scanner);
    }

    /** Remove a scanner by name */
    unregister(name: string): void {
        this.scanners.delete(name);
    }

    /** Retrieve a scanner by name */
    get(name: string): IScanner | undefined {
        return this.scanners.get(name);
    }

    /** Return all registered scanners in registration order */
    getAll(): IScanner[] {
        return Array.from(this.scanners.values());
    }

    /** Returns true when a scanner with the given name is registered */
    has(name: string): boolean {
        return this.scanners.has(name);
    }

    /** Number of registered scanners */
    get size(): number {
        return this.scanners.size;
    }

    /**
     * Run the scan with an automatic fallback chain.
     *
     * - If `primary` is provided, that scanner is tried first; on failure the
     *   remaining registered scanners are tried in registration order.
     * - If `primary` is omitted, scanners are tried in registration order.
     * - Throws if every scanner in the chain fails.
     */
    async scan(primary?: string): Promise<ScannerResult> {
        if (this.scanners.size === 0) {
            throw new Error('[ScannerRegistry] No scanners registered');
        }

        const all = Array.from(this.scanners.values());

        const ordered: IScanner[] = primary
            ? [
                  ...(this.scanners.has(primary) ? [this.scanners.get(primary)!] : []),
                  ...all.filter((s) => s.name !== primary),
              ]
            : all;

        const errors: string[] = [];

        for (const scanner of ordered) {
            try {
                logger.info(`[ScannerRegistry] Running scanner: ${scanner.name}`);
                const result = await scanner.scan();
                logger.success(
                    `[ScannerRegistry] Scanner [${scanner.name}] completed successfully`
                );
                return result;
            } catch (error: any) {
                const msg = `Scanner [${scanner.name}] failed: ${error.message}`;
                logger.warn(`[ScannerRegistry] ${msg}`);
                errors.push(msg);
            }
        }

        throw new Error(`[ScannerRegistry] All scanners failed:\n${errors.join('\n')}`);
    }
}

/** Module-level default registry instance (can be shared across the app) */
export const scannerRegistry = new ScannerRegistry();

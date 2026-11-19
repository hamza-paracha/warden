import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DEFAULT_REGISTRY } from './registry';
import { RISK_RANK, RiskSeverity } from './signals';

export interface SupplyChainPolicy {
    /** Releases younger than this are held back; most malicious releases are pulled within a day. */
    minReleaseAgeHours: number;
    /** Highest signal severity that still installs; at or above this the verdict is block. */
    blockAt: RiskSeverity;
    /** Package names or exact name@version specs whose signals are reviewed and accepted. */
    allow: string[];
    registry: string;
    /** Download and diff release contents (slower, much stronger evidence). */
    diff: boolean;
    /** Names resembling a popular package are accepted once they are this established. */
    establishedDownloads: number;
    maxPackages: number;
    concurrency: number;
    timeoutMs: number;
}

export const DEFAULT_POLICY: SupplyChainPolicy = {
    minReleaseAgeHours: 24,
    blockAt: 'high',
    allow: [],
    registry: DEFAULT_REGISTRY,
    diff: true,
    establishedDownloads: 50000,
    maxPackages: 300,
    concurrency: 6,
    timeoutMs: 30000,
};

const CONFIG_FILES = ['.wardenrc.json', '.wardenrc', 'warden.config.json'];

/** Read `supplyChain` from the nearest Warden config without touching the global logger. */
export function loadSupplyChainPolicy(
    directory = process.cwd(),
    overrides: Partial<SupplyChainPolicy> = {}
): SupplyChainPolicy {
    const candidates = [
        ...CONFIG_FILES.map((file) => path.join(directory, file)),
        path.join(os.homedir(), '.wardenrc.json'),
    ];
    let configured: Record<string, unknown> = {};
    for (const file of candidates) {
        if (!fs.existsSync(file)) continue;
        try {
            const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
            if (parsed?.supplyChain && typeof parsed.supplyChain === 'object')
                configured = parsed.supplyChain;
        } catch (error) {
            throw new Error(
                `Cannot read ${file}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
        break;
    }
    return normalizePolicy({ ...configured, ...stripUndefined(overrides) });
}

function stripUndefined<T extends object>(value: T): Partial<T> {
    return Object.fromEntries(
        Object.entries(value).filter(([, v]) => v !== undefined)
    ) as Partial<T>;
}

export function normalizePolicy(input: Record<string, unknown>): SupplyChainPolicy {
    const policy = { ...DEFAULT_POLICY };
    const number = (key: keyof SupplyChainPolicy, min: number) => {
        const value = input[key];
        if (value === undefined) return;
        if (typeof value !== 'number' || !Number.isFinite(value) || value < min)
            throw new Error(`supplyChain.${key} must be a number >= ${min}.`);
        (policy as any)[key] = value;
    };
    number('minReleaseAgeHours', 0);
    number('establishedDownloads', 0);
    number('maxPackages', 1);
    number('concurrency', 1);
    number('timeoutMs', 1000);
    if (input.blockAt !== undefined) {
        if (typeof input.blockAt !== 'string' || !(input.blockAt in RISK_RANK))
            throw new Error('supplyChain.blockAt must be low, medium, high, or critical.');
        policy.blockAt = input.blockAt as RiskSeverity;
    }
    if (input.allow !== undefined) {
        if (!Array.isArray(input.allow) || input.allow.some((v) => typeof v !== 'string'))
            throw new Error('supplyChain.allow must be an array of package names.');
        policy.allow = input.allow as string[];
    }
    if (input.registry !== undefined) {
        if (typeof input.registry !== 'string' || !/^https:\/\//.test(input.registry))
            throw new Error('supplyChain.registry must be an https URL.');
        policy.registry = input.registry.replace(/\/+$/, '');
    }
    if (input.diff !== undefined) {
        if (typeof input.diff !== 'boolean') throw new Error('supplyChain.diff must be a boolean.');
        policy.diff = input.diff;
    }
    return policy;
}

/** Policy from a trusted config file only (never from the candidate being reviewed). */
export function policyFromConfigText(text: string | undefined): SupplyChainPolicy {
    if (!text) return { ...DEFAULT_POLICY };
    const parsed = JSON.parse(text);
    return normalizePolicy(
        parsed?.supplyChain && typeof parsed.supplyChain === 'object' ? parsed.supplyChain : {}
    );
}

export function isAllowed(policy: SupplyChainPolicy, name: string, version?: string): boolean {
    return (
        policy.allow.includes(name) || (!!version && policy.allow.includes(`${name}@${version}`))
    );
}

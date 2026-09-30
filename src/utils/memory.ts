import { writeJsonAtomic } from '../services/artifacts';
import * as fs from 'fs';
import * as path from 'path';
import { MemoryHotspot, MemorySnapshot, ScanResult, Severity } from '../types';
import { SCAN_RESULTS_DIR, SEVERITY_PRIORITY } from '../constants';

interface MemoryStore {
    [repoKey: string]: {
        runCount: number;
        packages: Record<string, { occurrences: number; lastSeverity: Severity }>;
    };
}

const MEMORY_FILE = 'memory.json';

export class MemoryService {
    private readonly memoryPath: string;

    constructor(baseDir: string = path.resolve(process.cwd(), SCAN_RESULTS_DIR)) {
        this.memoryPath = path.join(baseDir, MEMORY_FILE);

        if (!fs.existsSync(baseDir)) {
            fs.mkdirSync(baseDir, { recursive: true });
        }
    }

    update(repoKey: string, scanResult: ScanResult): MemorySnapshot {
        const store = this.readStore();
        const repoMemory = store[repoKey] || { runCount: 0, packages: Object.create(null) };
        repoMemory.runCount += 1;

        for (const vulnerability of scanResult.vulnerabilities) {
            if (!vulnerability.packageName) {
                continue;
            }

            const current = repoMemory.packages[vulnerability.packageName] || {
                occurrences: 0,
                lastSeverity: vulnerability.severity,
            };

            current.occurrences += 1;
            if (
                SEVERITY_PRIORITY[vulnerability.severity] >= SEVERITY_PRIORITY[current.lastSeverity]
            ) {
                current.lastSeverity = vulnerability.severity;
            }

            repoMemory.packages[vulnerability.packageName] = current;
        }

        store[repoKey] = repoMemory;
        writeJsonAtomic(this.memoryPath, store);

        return {
            repoKey,
            runCount: repoMemory.runCount,
            topHotspots: Object.entries(repoMemory.packages)
                .map(
                    ([packageName, value]): MemoryHotspot => ({
                        packageName,
                        occurrences: value.occurrences,
                        lastSeverity: value.lastSeverity,
                    })
                )
                .sort((left, right) => {
                    if (right.occurrences !== left.occurrences) {
                        return right.occurrences - left.occurrences;
                    }

                    return (
                        SEVERITY_PRIORITY[right.lastSeverity] - SEVERITY_PRIORITY[left.lastSeverity]
                    );
                })
                .slice(0, 5),
        };
    }

    private readStore(): MemoryStore {
        if (!fs.existsSync(this.memoryPath)) {
            return Object.create(null);
        }

        try {
            const content = fs.readFileSync(this.memoryPath, 'utf-8');
            const parsed: unknown = JSON.parse(content);
            const store: MemoryStore = Object.create(null);
            if (!isRecord(parsed)) return store;
            for (const [repoKey, value] of Object.entries(parsed)) {
                if (!isRecord(value) || !isCount(value.runCount) || !isRecord(value.packages)) {
                    continue;
                }
                const packages: MemoryStore[string]['packages'] = Object.create(null);
                for (const [packageName, entry] of Object.entries(value.packages)) {
                    if (
                        isRecord(entry) &&
                        isCount(entry.occurrences) &&
                        typeof entry.lastSeverity === 'string' &&
                        Object.hasOwn(SEVERITY_PRIORITY, entry.lastSeverity)
                    ) {
                        packages[packageName] = {
                            occurrences: entry.occurrences,
                            lastSeverity: entry.lastSeverity as Severity,
                        };
                    }
                }
                store[repoKey] = { runCount: value.runCount, packages };
            }
            return store;
        } catch {
            return Object.create(null);
        }
    }
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isCount(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

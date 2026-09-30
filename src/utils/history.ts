import { writeJsonAtomic } from '../services/artifacts';
import * as fs from 'fs';
import * as path from 'path';
import { RunHistoryEntry, RunHistorySnapshot } from '../types';
import { SCAN_RESULTS_DIR } from '../constants';

const HISTORY_FILE = 'history.json';

export class RunHistoryService {
    private readonly historyPath: string;

    constructor(baseDir: string = path.resolve(process.cwd(), SCAN_RESULTS_DIR)) {
        this.historyPath = path.join(baseDir, HISTORY_FILE);
        if (!fs.existsSync(baseDir)) {
            fs.mkdirSync(baseDir, { recursive: true });
        }
    }

    append(entry: RunHistoryEntry): RunHistorySnapshot {
        const history = this.readAll();
        // Shared history may contain multiple repositories and scan modes.
        let previous: RunHistoryEntry | undefined;
        for (let index = history.length - 1; index >= 0; index--) {
            const candidate = history[index];
            if (
                candidate.mode === entry.mode &&
                (candidate.repository || candidate.targetPath) ===
                    (entry.repository || entry.targetPath)
            ) {
                previous = candidate;
                break;
            }
        }
        history.push(entry);
        writeJsonAtomic(this.historyPath, history);

        return {
            latest: entry,
            previous,
            trend: this.computeTrend(previous, entry),
        };
    }

    readAll(): RunHistoryEntry[] {
        if (!fs.existsSync(this.historyPath)) {
            return [];
        }

        try {
            const content = fs.readFileSync(this.historyPath, 'utf-8');
            const parsed = JSON.parse(content);
            return Array.isArray(parsed) ? parsed.filter(isHistoryEntry) : [];
        } catch {
            return [];
        }
    }

    private computeTrend(
        previous: RunHistoryEntry | undefined,
        latest: RunHistoryEntry
    ): RunHistorySnapshot['trend'] {
        if (!previous) {
            return 'first-run';
        }

        // Risk takes precedence: fewer findings must not hide higher severity.
        if (latest.riskScore !== previous.riskScore) {
            return latest.riskScore < previous.riskScore ? 'improving' : 'worsening';
        }
        if (latest.totalVulnerabilities !== previous.totalVulnerabilities) {
            return latest.totalVulnerabilities < previous.totalVulnerabilities
                ? 'improving'
                : 'worsening';
        }

        return 'unchanged';
    }
}

function isHistoryEntry(value: unknown): value is RunHistoryEntry {
    if (!value || typeof value !== 'object') return false;
    const entry = value as Record<string, unknown>;
    const counts = [
        'totalVulnerabilities',
        'critical',
        'high',
        'medium',
        'low',
        'appliedFixes',
        'attemptedFixes',
        'autoFixableCount',
        'manualCount',
    ];
    return (
        typeof entry.timestamp === 'string' &&
        (entry.mode === 'sast' || entry.mode === 'dast') &&
        typeof entry.targetPath === 'string' &&
        (entry.repository === undefined || typeof entry.repository === 'string') &&
        typeof entry.riskScore === 'number' &&
        Number.isFinite(entry.riskScore) &&
        entry.riskScore >= 0 &&
        entry.riskScore <= 100 &&
        counts.every(
            (key) =>
                typeof entry[key] === 'number' &&
                Number.isSafeInteger(entry[key]) &&
                entry[key] >= 0
        )
    );
}

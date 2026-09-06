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
        const previous = history[history.length - 1];
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
            return Array.isArray(parsed) ? parsed : [];
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

        if (
            latest.riskScore < previous.riskScore ||
            latest.totalVulnerabilities < previous.totalVulnerabilities
        ) {
            return 'improving';
        }

        if (
            latest.riskScore > previous.riskScore ||
            latest.totalVulnerabilities > previous.totalVulnerabilities
        ) {
            return 'worsening';
        }

        return 'unchanged';
    }
}

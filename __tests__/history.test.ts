import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RunHistoryService } from '../src/utils/history';
import { RunHistoryEntry } from '../src/types';

describe('RunHistoryService', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-history-'));

    afterAll(() => {
        fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('appends entries and computes trend', () => {
        const service = new RunHistoryService(tempDir);
        const first: RunHistoryEntry = {
            timestamp: '2026-05-09T12:00:00.000Z',
            mode: 'sast',
            targetPath: '/tmp/project',
            totalVulnerabilities: 5,
            critical: 1,
            high: 2,
            medium: 1,
            low: 1,
            appliedFixes: 1,
            attemptedFixes: 2,
            autoFixableCount: 3,
            manualCount: 2,
            riskScore: 90,
        };

        const second: RunHistoryEntry = {
            ...first,
            timestamp: '2026-05-10T12:00:00.000Z',
            totalVulnerabilities: 2,
            critical: 0,
            high: 1,
            medium: 1,
            low: 0,
            appliedFixes: 2,
            attemptedFixes: 2,
            autoFixableCount: 1,
            manualCount: 1,
            riskScore: 40,
        };

        expect(service.append(first).trend).toBe('first-run');
        expect(service.append(second).trend).toBe('improving');
        expect(service.readAll()).toHaveLength(2);
    });
});

describe('history comparisons', () => {
    let directory: string;
    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-history-comparison-'));
    });
    afterEach(() => {
        fs.rmSync(directory, { recursive: true, force: true });
    });
    const entry: RunHistoryEntry = {
        timestamp: '2026-09-29T00:00:00Z',
        mode: 'sast',
        targetPath: '/tmp/a',
        totalVulnerabilities: 5,
        critical: 0,
        high: 0,
        medium: 0,
        low: 5,
        appliedFixes: 0,
        attemptedFixes: 0,
        autoFixableCount: 0,
        manualCount: 5,
        riskScore: 50,
    };
    it('uses the latest run for the same repository and mode', () => {
        const service = new RunHistoryService(directory);
        const first = { ...entry, repository: 'owner/a' };
        service.append(first);
        expect(service.append({ ...entry, repository: 'owner/b' }).trend).toBe('first-run');
        expect(service.append({ ...first, mode: 'dast' }).trend).toBe('first-run');
        const result = service.append({ ...first, targetPath: '/tmp/new-checkout', riskScore: 90 });
        expect(result.previous).toEqual(first);
        expect(result.trend).toBe('worsening');
    });
    it('separates local projects without repository metadata', () => {
        const service = new RunHistoryService(directory);
        service.append(entry);
        expect(service.append({ ...entry, targetPath: '/tmp/b' }).trend).toBe('first-run');
        expect(service.append({ ...entry, riskScore: 40 }).trend).toBe('improving');
    });
    it.each([
        [90, 1, 'worsening'],
        [20, 9, 'improving'],
        [50, 4, 'improving'],
        [50, 6, 'worsening'],
        [50, 5, 'unchanged'],
    ])('prioritizes risk %s with %s findings', (riskScore, totalVulnerabilities, expected) => {
        const service = new RunHistoryService(directory);
        service.append(entry);
        expect(
            service.append({
                ...entry,
                riskScore: Number(riskScore),
                totalVulnerabilities: Number(totalVulnerabilities),
            }).trend
        ).toBe(expected);
    });
    it('skips malformed saved entries', () => {
        fs.writeFileSync(
            path.join(directory, 'history.json'),
            JSON.stringify([
                entry,
                null,
                {},
                { ...entry, riskScore: 'low' },
                { ...entry, totalVulnerabilities: -1 },
            ])
        );
        const service = new RunHistoryService(directory);
        expect(service.readAll()).toEqual([entry]);
        expect(service.append({ ...entry, riskScore: 60 }).previous).toEqual(entry);
    });
});

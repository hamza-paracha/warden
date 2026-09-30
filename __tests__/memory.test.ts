import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { MemoryService } from '../src/utils/memory';
import { ScanResult } from '../src/types';

describe('MemoryService', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-memory-'));

    afterAll(() => {
        fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('tracks recurring vulnerable packages by repo key', () => {
        const service = new MemoryService(tempDir);
        const result: ScanResult = {
            timestamp: '2026-05-09T12:00:00.000Z',
            vulnerabilities: [
                {
                    id: '1',
                    title: 'Issue 1',
                    severity: 'high',
                    packageName: 'lodash',
                    version: '1.0.0',
                    fixedIn: ['1.0.1'],
                    description: 'desc',
                },
                {
                    id: '2',
                    title: 'Issue 2',
                    severity: 'critical',
                    packageName: 'lodash',
                    version: '1.0.0',
                    fixedIn: ['1.0.1'],
                    description: 'desc',
                },
            ],
            summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0 },
        };

        service.update('owner/repo', result);
        const snapshot = service.update('owner/repo', result);

        expect(snapshot.runCount).toBe(2);
        expect(snapshot.topHotspots[0].packageName).toBe('lodash');
        expect(snapshot.topHotspots[0].occurrences).toBe(4);
        expect(snapshot.topHotspots[0].lastSeverity).toBe('critical');
    });
});

describe('memory recovery', () => {
    let directory: string;
    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-memory-recovery-'));
    });
    afterEach(() => {
        fs.rmSync(directory, { recursive: true, force: true });
    });
    const scan: ScanResult = {
        timestamp: '2026-09-29T00:00:00Z',
        vulnerabilities: ['__proto__', 'constructor', 'toString'].map((packageName) => ({
            id: packageName,
            packageName,
            title: 'Issue',
            severity: 'high',
            version: '1',
            fixedIn: [],
            description: '',
        })),
        summary: { total: 3, critical: 0, high: 3, medium: 0, low: 0 },
    };
    it.each(['__proto__', 'constructor', 'toString'])(
        'round-trips reserved repository key %s',
        (key) => {
            const service = new MemoryService(directory);
            service.update(key, scan);
            const result = new MemoryService(directory).update(key, scan);
            expect(result.runCount).toBe(2);
            expect(result.topHotspots.map((item) => item.packageName)).toEqual([
                '__proto__',
                'constructor',
                'toString',
            ]);
            expect(result.topHotspots.every((item) => item.occurrences === 2)).toBe(true);
            expect(Object.prototype).not.toHaveProperty('occurrences');
        }
    );
    it('skips malformed entries while preserving valid counters', () => {
        fs.writeFileSync(
            path.join(directory, 'memory.json'),
            JSON.stringify({
                broken: { runCount: 'many', packages: null },
                valid: {
                    runCount: 4,
                    packages: {
                        good: { occurrences: 10, lastSeverity: 'critical' },
                        bad: null,
                        negative: { occurrences: -1, lastSeverity: 'high' },
                        unknown: { occurrences: 3, lastSeverity: 'constructor' },
                    },
                },
            })
        );
        const service = new MemoryService(directory);
        const result = service.update('valid', { ...scan, vulnerabilities: [] });
        expect(result).toMatchObject({
            runCount: 5,
            topHotspots: [{ packageName: 'good', occurrences: 10 }],
        });
        expect(result.topHotspots).toHaveLength(1);
        expect(service.update('broken', scan).runCount).toBe(1);
    });
    it.each(['null', '[]', '{broken'])('recovers from invalid store %s', (content) => {
        fs.writeFileSync(path.join(directory, 'memory.json'), content);
        expect(new MemoryService(directory).update('repo', scan).runCount).toBe(1);
    });
});

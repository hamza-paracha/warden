import fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    compareBaseline,
    createBaselineSnapshot,
    hasBaselineRegression,
    readBaseline,
    readScanResult,
    writeBaseline,
} from '../src/utils/baseline';
import { ScanResult } from '../src/types';

function scanResult(overrides: Partial<ScanResult> = {}): ScanResult {
    const vulnerabilities = overrides.vulnerabilities || [
        {
            id: 'SNYK-JS-LODASH-1',
            title: 'Prototype pollution',
            severity: 'low',
            packageName: 'lodash',
            version: '4.17.10',
            fixedIn: ['4.17.21'],
            description: 'Prototype pollution in lodash',
            ecosystem: 'npm',
        },
        {
            id: 'SNYK-JS-MINIMIST-2',
            title: 'Argument injection',
            severity: 'medium',
            packageName: 'minimist',
            version: '1.2.0',
            fixedIn: ['1.2.8'],
            description: 'Argument injection in minimist',
            ecosystem: 'npm',
        },
    ];

    return {
        timestamp: '2026-05-11T12:00:00.000Z',
        scanner: 'snyk',
        scanMode: 'sast',
        projectPath: '/tmp/project',
        vulnerabilities,
        summary: {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter(
                (vulnerability) => vulnerability.severity === 'critical'
            ).length,
            high: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'high')
                .length,
            medium: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'medium')
                .length,
            low: vulnerabilities.filter((vulnerability) => vulnerability.severity === 'low').length,
        },
    };
}

describe('baseline', () => {
    it('compares new, resolved, and worsened findings against a baseline', () => {
        const baseline = createBaselineSnapshot(scanResult());
        const currentScan = scanResult({
            vulnerabilities: [
                {
                    id: 'SNYK-JS-LODASH-1',
                    title: 'Prototype pollution',
                    severity: 'high',
                    packageName: 'lodash',
                    version: '4.17.10',
                    fixedIn: ['4.17.21'],
                    description: 'Prototype pollution in lodash',
                    ecosystem: 'npm',
                },
                {
                    id: 'SNYK-JS-EXPRESS-3',
                    title: 'Open redirect',
                    severity: 'critical',
                    packageName: 'express',
                    version: '4.17.0',
                    fixedIn: ['4.18.3'],
                    description: 'Open redirect in express',
                    ecosystem: 'npm',
                },
            ],
        });

        const comparison = compareBaseline(currentScan, baseline);

        expect(comparison.summary.new).toBe(1);
        expect(comparison.summary.worsened).toBe(1);
        expect(comparison.summary.resolved).toBe(1);
        expect(comparison.worsenedFindings[0].severityChanged).toEqual({
            from: 'low',
            to: 'high',
        });
        expect(hasBaselineRegression(comparison, 'high')).toBe(true);
    });

    it('honors the severity threshold when deciding whether a baseline regressed', () => {
        const baseline = createBaselineSnapshot(scanResult({ vulnerabilities: [] }));
        const currentScan = scanResult({
            vulnerabilities: [
                {
                    id: 'SNYK-JS-DEBUG-4',
                    title: 'Information exposure',
                    severity: 'medium',
                    packageName: 'debug',
                    version: '2.6.0',
                    fixedIn: ['4.3.7'],
                    description: 'Information exposure in debug',
                    ecosystem: 'npm',
                },
            ],
        });

        const comparison = compareBaseline(currentScan, baseline);

        expect(hasBaselineRegression(comparison, 'high')).toBe(false);
        expect(hasBaselineRegression(comparison, 'medium')).toBe(true);
    });

    it('writes and reads baseline and scan result files', () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-baseline-'));
        const scanPath = path.join(tempDir, 'scan-results.json');
        const baselinePath = path.join(tempDir, '.warden-baseline.json');
        const result = scanResult();

        try {
            fs.writeFileSync(scanPath, JSON.stringify(result, null, 2), 'utf-8');
            const baseline = writeBaseline(readScanResult(scanPath), baselinePath);

            expect(readBaseline(baselinePath).findings).toHaveLength(2);
            expect(baseline.summary.total).toBe(2);
        } finally {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
});

it('preserves the previous baseline when atomic replacement fails', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-baseline-atomic-'));
    const filename = path.join(directory, 'baseline.json');
    const initial = writeBaseline(scanResult(), filename);
    const rename = jest.spyOn(fs, 'renameSync').mockImplementation(() => {
        throw new Error('disk failure');
    });
    try {
        expect(() => writeBaseline(scanResult({ vulnerabilities: [] }), filename)).toThrow(
            'disk failure'
        );
        expect(readBaseline(filename)).toEqual(initial);
        expect(fs.readdirSync(directory)).toEqual(['baseline.json']);
    } finally {
        rename.mockRestore();
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

import { isSeverityAtLeast, selectVulnerabilitiesForFix } from '../src/utils/scan-results';
import { Vulnerability } from '../src/types';

const vulnerabilities: Vulnerability[] = [
    {
        id: 'low-1',
        title: 'Low severity issue',
        severity: 'low',
        packageName: 'a',
        version: '1.0.0',
        fixedIn: ['1.0.1'],
        description: 'low',
        cvssScore: 2,
    },
    {
        id: 'high-1',
        title: 'High severity issue',
        severity: 'high',
        packageName: 'b',
        version: '1.0.0',
        fixedIn: ['1.1.0'],
        description: 'high',
        cvssScore: 7.5,
    },
    {
        id: 'critical-1',
        title: 'Critical severity issue',
        severity: 'critical',
        packageName: 'c',
        version: '1.0.0',
        fixedIn: ['2.0.0'],
        description: 'critical',
        cvssScore: 9.8,
    },
    {
        id: 'high-2',
        title: 'Higher CVSS high severity issue',
        severity: 'high',
        packageName: 'd',
        version: '1.0.0',
        fixedIn: ['1.2.0'],
        description: 'high-2',
        cvssScore: 8.4,
    },
];

describe('scan-results helpers', () => {
    describe('isSeverityAtLeast', () => {
        it('treats higher severities as matching the threshold', () => {
            expect(isSeverityAtLeast('critical', 'high')).toBe(true);
            expect(isSeverityAtLeast('high', 'high')).toBe(true);
            expect(isSeverityAtLeast('medium', 'high')).toBe(false);
        });
    });

    describe('selectVulnerabilitiesForFix', () => {
        it('filters out lower severities and respects the fix limit', () => {
            const selected = selectVulnerabilitiesForFix(vulnerabilities, 'high', 2);
            expect(selected.map((vulnerability) => vulnerability.id)).toEqual([
                'critical-1',
                'high-2',
            ]);
        });

        it('returns an empty list when maxFixes is zero', () => {
            expect(selectVulnerabilitiesForFix(vulnerabilities, 'low', 0)).toEqual([]);
        });
    });
});

it('matches stable full sorting across large inputs, ties, thresholds, and limits', () => {
    const ranks = { low: 1, medium: 2, high: 3, critical: 4 };
    let seed = 42;
    const input = Array.from({ length: 2000 }, (_, index) => {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        return {
            ...vulnerabilities[(seed >>> 16) % vulnerabilities.length],
            id: String(index),
            cvssScore: seed % 11,
        };
    });
    const snapshot = [...input];
    for (const severity of ['low', 'medium', 'high', 'critical'] as const) {
        for (const limit of [0, 1, 2, 10, 3000]) {
            const expected = input
                .filter((v) => ranks[v.severity] >= ranks[severity])
                .sort(
                    (a, b) =>
                        ranks[b.severity] - ranks[a.severity] ||
                        (b.cvssScore ?? 0) - (a.cvssScore ?? 0)
                )
                .slice(0, limit);
            expect(selectVulnerabilitiesForFix(input, severity, limit)).toEqual(expected);
        }
    }
    expect(input).toEqual(snapshot);
});
it.each([NaN, Infinity, -1, 1.5])('rejects invalid fix limit %s', (limit) => {
    expect(() => selectVulnerabilitiesForFix(vulnerabilities, 'low', limit)).toThrow();
});

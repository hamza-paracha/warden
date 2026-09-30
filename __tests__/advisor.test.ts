import { buildRemediationPlan, calculateRiskScore, createHistoryEntry } from '../src/utils/advisor';
import { ScanResult, WardenRunResult } from '../src/types';

const scanResult: ScanResult = {
    timestamp: '2026-05-09T12:00:00.000Z',
    scanner: 'snyk',
    vulnerabilities: [
        {
            id: 'V1',
            title: 'Critical issue',
            severity: 'critical',
            packageName: 'lodash',
            version: '1.0.0',
            fixedIn: ['1.0.1'],
            description: 'critical',
            cvssScore: 9.8,
        },
        {
            id: 'V2',
            title: 'Manual issue',
            severity: 'high',
            packageName: 'transitive-lib',
            version: '2.0.0',
            fixedIn: [],
            description: 'manual',
            exploitAvailable: true,
        },
    ],
    summary: {
        total: 2,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
    },
};

describe('advisor', () => {
    it('builds an actionable remediation plan', () => {
        const plan = buildRemediationPlan(scanResult, {
            appliedFixes: 0,
            attemptedFixes: 1,
            warnings: ['GITHUB_TOKEN is not set'],
        });

        expect(plan.riskScore).toBeGreaterThan(0);
        expect(plan.posture).toBe('critical');
        expect(plan.autoFixableCount).toBe(1);
        expect(plan.manualCount).toBe(1);
        expect(plan.immediateActions.length).toBeGreaterThan(0);
        expect(plan.strategicImprovements.some((item) => item.includes('GitHub credentials'))).toBe(
            true
        );
    });

    it('creates a history entry from a run result', () => {
        const runResult: Pick<
            WardenRunResult,
            | 'mode'
            | 'targetPath'
            | 'repository'
            | 'appliedFixes'
            | 'attemptedFixes'
            | 'remediationPlan'
        > = {
            mode: 'sast',
            targetPath: '/tmp/project',
            repository: 'owner/repo',
            appliedFixes: 1,
            attemptedFixes: 1,
            remediationPlan: buildRemediationPlan(scanResult, {
                appliedFixes: 1,
                attemptedFixes: 1,
                warnings: [],
            }),
        };

        const entry = createHistoryEntry(scanResult, runResult);
        expect(entry.totalVulnerabilities).toBe(2);
        expect(entry.autoFixableCount).toBe(1);
        expect(entry.manualCount).toBe(1);
        expect(entry.mode).toBe('sast');
    });
});

it('preserves counts, risk weights, and the first six distinct manual packages', () => {
    const vulnerabilities = Array.from({ length: 20 }, (_, index) => ({
        ...scanResult.vulnerabilities[0],
        packageName: `package-${Math.floor(index / 2)}`,
        severity: 'low' as const,
        cvssScore: 0,
        fixedIn: index === 19 ? ['2.0.0'] : [],
        exploitAvailable: index === 18,
    }));
    const input = { ...scanResult, vulnerabilities };
    const plan = buildRemediationPlan(input, { appliedFixes: 0, attemptedFixes: 0, warnings: [] });
    expect(plan.autoFixableCount).toBe(1);
    expect(plan.manualCount).toBe(19);
    expect(plan.exploitCount).toBe(1);
    expect(plan.riskScore).toBe(100);
    expect(plan.manualFollowUps).toEqual(
        Array.from(
            { length: 6 },
            (_, index) => `Investigate manual remediation path for package-${index}`
        )
    );
    expect(plan.immediateActions.some((action) => action.title.includes('Escalate'))).toBe(true);
    expect(calculateRiskScore({ ...input, vulnerabilities: [] })).toBe(0);
    expect(
        calculateRiskScore({
            ...input,
            vulnerabilities: [
                {
                    ...vulnerabilities[0],
                    cvssScore: 2.4,
                    exploitAvailable: true,
                },
            ],
        })
    ).toBe(52);
});

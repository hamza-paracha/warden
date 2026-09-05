import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import fixture from './fixtures/sast-scan-result.json';

jest.mock('../src/utils/config', () => ({
    getConfig: jest.fn(() => ({
        get: jest.fn((key: string) => {
            if (key === 'logging') {
                return { level: 'info' };
            }
            return {};
        }),
        getConfig: jest.fn(() => ({
            policy: {
                failOnSeverity: 'critical',
                failOnPosture: 'critical',
                requireApprovalAboveSeverity: 'high',
            },
        })),
    })),
}));

jest.mock('../src/agents/watchman/snyk', () => ({
    SnykScanner: jest.fn().mockImplementation(() => ({
        test: jest.fn().mockResolvedValue(fixture),
        printSummary: jest.fn(),
    })),
}));

jest.mock('../src/agents/watchman/npm-audit', () => ({
    NpmAuditScanner: jest.fn().mockImplementation(() => ({
        scan: jest.fn().mockResolvedValue(fixture),
    })),
}));

const diagnoseMock = jest.fn().mockResolvedValue([
    {
        vulnerabilityId: 'CRIT-1',
        description: 'Prototype Pollution in lodash@4.17.15 (CRITICAL)',
        suggestedFix: 'Update lodash from 4.17.15 to 4.17.21',
        filesToModify: ['package.json'],
        fixInstruction: {
            packageName: 'lodash',
            currentVersion: '4.17.15',
            targetVersion: '4.17.21',
        },
    },
    {
        vulnerabilityId: 'HIGH-1',
        description: 'SSRF in axios@0.21.0 (HIGH)',
        suggestedFix: 'Update axios from 0.21.0 to 0.21.1',
        filesToModify: ['package.json'],
        fixInstruction: {
            packageName: 'axios',
            currentVersion: '0.21.0',
            targetVersion: '0.21.1',
        },
    },
]);

const applyFixMock = jest.fn();

jest.mock('../src/agents/engineer', () => ({
    EngineerAgent: jest.fn().mockImplementation(() => ({
        diagnose: diagnoseMock,
        applyFix: applyFixMock,
    })),
}));

jest.mock('../src/agents/diplomat', () => ({
    DiplomatAgent: jest.fn().mockImplementation(() => ({
        pushBranch: jest.fn().mockResolvedValue(true),
        createPullRequest: jest.fn().mockResolvedValue('https://example.com/pr/1'),
        generatePrTitle: jest.fn().mockReturnValue('[SECURITY] Mock PR'),
        generatePrBody: jest.fn().mockReturnValue('Mock body'),
    })),
}));

describe('SastWorkflow integration', () => {
    const originalCwd = process.cwd();

    afterEach(() => {
        process.chdir(originalCwd);
        jest.clearAllMocks();
    });

    it('propagates scanner errors without attempting fixes on demo data', async () => {
        const { NpmAuditScanner } = await import('../src/agents/watchman/npm-audit');
        (NpmAuditScanner as jest.Mock).mockImplementationOnce(() => ({
            scan: jest.fn().mockRejectedValue(new Error('registry unavailable')),
        }));
        const { SastWorkflow } = await import('../src/workflows/sast-workflow');
        await expect(
            new SastWorkflow().run({
                targetPath: originalCwd,
                dryRun: false,
                scanner: 'npm-audit',
                minSeverity: 'high',
                maxFixes: 1,
                verbose: false,
            })
        ).rejects.toThrow('registry unavailable');
        expect(diagnoseMock).not.toHaveBeenCalled();
        expect(applyFixMock).not.toHaveBeenCalled();
        expect(process.cwd()).toBe(originalCwd);
    });

    it('blocks risky fixes until approval is provided', async () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-sast-'));
        fs.writeFileSync(
            path.join(tempDir, 'package.json'),
            JSON.stringify({ name: 'fixture-app', version: '1.0.0' }),
            'utf-8'
        );
        process.chdir(tempDir);

        const { SastWorkflow } = await import('../src/workflows/sast-workflow');
        const workflow = new SastWorkflow();
        const result = await workflow.run({
            targetPath: tempDir,
            dryRun: false,
            scanner: 'snyk',
            minSeverity: 'high',
            maxFixes: 1,
            verbose: false,
            ci: false,
        });

        expect(result.appliedFixes).toBe(0);
        expect(result.warnings.some((warning) => warning.includes('Approval required'))).toBe(true);
        expect(applyFixMock).not.toHaveBeenCalled();
    });

    it('selects only the configured number of high-priority fixes in dry-run mode', async () => {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-sast-'));
        fs.writeFileSync(
            path.join(tempDir, 'package.json'),
            JSON.stringify({ name: 'fixture-app', version: '1.0.0' }),
            'utf-8'
        );
        process.chdir(tempDir);

        const { SastWorkflow } = await import('../src/workflows/sast-workflow');
        const workflow = new SastWorkflow();
        const result = await workflow.run({
            targetPath: tempDir,
            dryRun: true,
            scanner: 'snyk',
            minSeverity: 'high',
            maxFixes: 1,
            verbose: false,
            ci: false,
            approvalToken: 'approved',
        });

        expect(result.selectedVulnerabilityIds).toEqual(['CRIT-1']);
        expect(result.attemptedFixes).toBe(1);
    });
});

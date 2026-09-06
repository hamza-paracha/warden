import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SnykScanner } from '../src/agents/watchman/snyk';
import { NpmAuditScanner } from '../src/agents/watchman/npm-audit';
import { PipAuditScanner } from '../src/agents/watchman/pip-audit';
import { runProcess } from '../src/services/process';

jest.mock('../src/services/process', () => ({ runProcess: jest.fn() }));
jest.mock('../src/utils/logger', () => ({
    logger: { watchman: jest.fn(), success: jest.fn(), error: jest.fn(), warn: jest.fn() },
}));
const run = jest.mocked(runProcess);
let directory: string;
beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-scanner-'));
    run.mockReset();
});
afterEach(() => fs.rmSync(directory, { recursive: true, force: true }));

it.each(['{}', 'null', '[]', '{"error":"auth failed"}', '{"ok":false}'])(
    'rejects invalid Snyk reports: %s',
    (json) => {
        expect(() => new SnykScanner().parseSnykOutput(json)).toThrow();
    }
);
it('merges Snyk multi-project reports and normalizes unknown severity', () => {
    const result = new SnykScanner().parseSnykOutput(
        JSON.stringify([
            { vulnerabilities: [{ id: 'A', severity: 'HIGH' }] },
            { packageManager: 'pip', vulnerabilities: [{ id: 'B', severity: 'moderate' }] },
        ])
    );
    expect(result.summary).toEqual({ total: 2, critical: 0, high: 1, medium: 1, low: 0 });
    expect(result.vulnerabilities[1].ecosystem).toBe('python');
});
it('does not overwrite a previous report after scanner failure', async () => {
    fs.mkdirSync(path.join(directory, 'scan-results'));
    const latest = path.join(directory, 'scan-results/scan-results.json');
    fs.writeFileSync(latest, 'previous report');
    run.mockRejectedValue(new Error('authentication failed'));
    await expect(new SnykScanner({ projectPath: directory }).test()).rejects.toThrow(
        'authentication failed'
    );
    expect(fs.readFileSync(latest, 'utf8')).toBe('previous report');
    expect(run).toHaveBeenCalledTimes(1);
});
it('persists retry metadata after a successful retry', async () => {
    run.mockRejectedValueOnce({ code: 'ECONNREFUSED', message: 'offline' }).mockResolvedValueOnce({
        stdout: '{"vulnerabilities":[]}',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
    });
    const result = await new SnykScanner({ projectPath: directory, retryDelayMs: 0 }).test();
    const saved = JSON.parse(
        fs.readFileSync(path.join(directory, 'scan-results/scan-results.json'), 'utf8')
    );
    expect(result.metadata?.retryCount).toBe(1);
    expect(saved).toEqual(result);
});
it('does not apply a parent package fix version to a child dependency', () => {
    const result = new NpmAuditScanner().formatVulnerabilities({
        vulnerabilities: {
            child: {
                name: 'child',
                severity: 'high',
                fixAvailable: { name: 'parent', version: '3.0.0' },
            },
        },
    });
    expect(result[0].fixedIn).toEqual([]);
});
it.each(['{}', 'null', '{"error":"unavailable"}', '{"dependencies":{}}'])(
    'rejects malformed pip-audit reports: %s',
    (json) => {
        expect(() => new PipAuditScanner().parseAuditOutput(json)).toThrow();
    }
);
it('runs npm in the captured project directory with configured timeout', async () => {
    run.mockResolvedValueOnce({
        stdout: '{"vulnerabilities":{}}',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
    });
    await new NpmAuditScanner({ projectPath: directory, timeoutMs: 1234 }).scan();
    expect(run).toHaveBeenCalledWith(
        'npm',
        ['audit', '--json'],
        expect.objectContaining({ cwd: directory, timeout: 1234, allowedExitCodes: [0, 1] })
    );
});

it('does not infer low severity from the word overflow', () => {
    const scan = new PipAuditScanner().parseAuditOutput(
        JSON.stringify({
            dependencies: [
                {
                    name: 'example',
                    version: '1',
                    vulns: [{ id: 'X', description: 'Buffer overflow' }],
                },
            ],
        })
    );
    expect(scan.vulnerabilities[0].severity).toBe('medium');
});
it('rejects incomplete dependency entries instead of silently reporting clean', () => {
    expect(() =>
        new PipAuditScanner().parseAuditOutput('{"dependencies":[{"name":"skipped"}]}')
    ).toThrow('incomplete');
});

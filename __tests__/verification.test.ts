import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import {
    verifyChange,
    parseAudit,
    compareFindings,
    advisoryId,
    VerifyOptions,
} from '../src/verification';
import { runProcess, ProcessError } from '../src/services/process';

jest.mock('../src/services/process', () => ({
    ...jest.requireActual('../src/services/process'),
    runProcess: jest.fn(),
}));
const realRun = jest.requireActual('../src/services/process').runProcess;
const mocked = jest.mocked(runProcess);
const advisory = 'GHSA-abcd-1234-5678';
function audit(
    entries: Array<{ name?: string; severity?: string; source?: number; id?: string }> = []
) {
    const vulnerabilities: Record<string, any> = {};
    for (const entry of entries) {
        const name = entry.name || 'example';
        const severity = entry.severity || 'high';
        vulnerabilities[name] ||= { name, severity, via: [] };
        vulnerabilities[name].via.push({
            source: entry.source || 42,
            severity,
            url: `https://github.com/advisories/${entry.id || advisory}`,
            title: 'Fixture issue',
        });
    }
    return JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities,
        metadata: { vulnerabilities: { total: Object.keys(vulnerabilities).length } },
    });
}
const result = (stdout = '', exitCode = 0) => ({ stdout, stderr: '', exitCode, durationMs: 1 });
let root: string;
let repo: string;
let base: string;
let head: string;
let options: VerifyOptions;
let baseAudit: string;
let headAudit: string;
let fail: string;
const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'warden verification '));
    repo = path.join(root, 'repo with spaces');
    fs.mkdirSync(repo);
    git('init', '--quiet');
    git('config', 'user.email', 'fixture@example.com');
    git('config', 'user.name', 'Fixture');
    const manifest = { name: 'fixture', version: '1.0.0', scripts: { test: 'node test.js' } };
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(manifest));
    fs.writeFileSync(
        path.join(repo, 'package-lock.json'),
        JSON.stringify({
            name: 'fixture',
            lockfileVersion: 3,
            packages: { '': { version: '1.0.0' } },
        })
    );
    fs.writeFileSync(path.join(repo, 'test.js'), 'process.exit(0);');
    git('add', '.');
    git('commit', '--quiet', '-m', 'base');
    base = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(repo, 'test.js'), '// Candidate\nprocess.exit(0);');
    git('add', '.');
    git('commit', '--quiet', '-m', 'head');
    head = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(repo, 'local.txt'), 'keep me');
    fs.writeFileSync(path.join(repo, 'test.js'), '// unstaged user work');
    baseAudit = audit([{}]);
    headAudit = audit();
    fail = '';
    options = {
        repository: repo,
        base,
        head,
        advisories: [advisory],
        testCommand: ['npm', 'test'],
        runner: 'trusted-host',
        timeoutMs: 5000,
        severity: 'high',
        output: path.join(root, 'evidence'),
    };
    mocked.mockImplementation(async (exe, args = [], config = {}) => {
        if (exe === 'git' || exe === 'tar') return realRun(exe, args, config);
        if (exe === 'npm' && args[0] === '--version') return result('11.0.0');
        if (exe === 'npm' && args[0] === 'audit') {
            if (fail === 'scan')
                throw new ProcessError('npm', 2, '{}', 'unavailable', false, null, 'failed');
            return result(config.cwd?.endsWith('base') ? baseAudit : headAudit, 1);
        }
        if (exe === 'npm' && args[0] === 'ci') {
            if (fail === 'install') throw new Error('install failed');
            return result();
        }
        if (exe === 'npm' && args[0] === 'test') {
            if (fail === 'tests')
                throw new ProcessError(
                    'npm',
                    1,
                    '',
                    'assertion failed',
                    false,
                    null,
                    'test failed'
                );
            if (fail === 'timeout')
                throw new ProcessError('npm', 'ETIMEDOUT', '', '', true, 'SIGTERM', 'timeout');
            if (fail === 'mutation')
                fs.writeFileSync(path.join(config.cwd!, 'package-lock.json'), '{}');
            return result();
        }
        if (exe === 'docker') {
            if (fail === 'docker') throw new Error('Docker is unavailable');
            return result(args[0] === 'image' ? 'sha256:' + 'a'.repeat(64) : '');
        }
        throw new Error(`Unexpected command: ${exe} ${args.join(' ')}`);
    });
});
afterEach(() => {
    jest.clearAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
});

it('verifies a fix with provenance and artifacts without modifying the user checkout or index', async () => {
    const before = git('status', '--porcelain');
    const evidence = await verifyChange(options);
    expect(evidence.status).toBe('passed');
    expect(evidence.exitCode).toBe(0);
    expect(evidence.revisions.base.sha).toBe(base);
    expect(evidence.revisions.head.lockfileSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(evidence.changedFiles).toEqual(['test.js']);
    expect(evidence.checks.tests.status).toBe('passed');
    expect(git('status', '--porcelain')).toBe(before);
    expect(git('rev-parse', 'HEAD')).toBe(head);
    expect(fs.readFileSync(path.join(repo, 'local.txt'), 'utf8')).toBe('keep me');
    expect(fs.readFileSync(path.join(options.output, 'verification.md'), 'utf8')).toContain(
        'PASSED'
    );
    expect(
        JSON.parse(fs.readFileSync(path.join(options.output, 'verification.json'), 'utf8')).status
    ).toBe('passed');
    expect(fs.existsSync(mocked.mock.calls.find(([exe]) => exe === 'tar')![1]![3] as string)).toBe(
        false
    );
});
it('fails a version bump that leaves the same advisory present', async () => {
    headAudit = audit([{}]);
    const evidence = await verifyChange(options);
    expect(evidence.status).toBe('failed');
    expect(evidence.comparison?.remainingTargets).toEqual([advisory.toUpperCase()]);
});
it('fails a newly introduced high severity issue even when the target disappears', async () => {
    headAudit = audit([{ name: 'other', id: 'GHSA-9999-8888-7777' }]);
    expect((await verifyChange(options)).status).toBe('failed');
});
it('allows an unchanged unrelated vulnerability and reports it separately', async () => {
    const other = { name: 'other', id: 'GHSA-9999-8888-7777' };
    baseAudit = audit([{}, other]);
    headAudit = audit([other]);
    const evidence = await verifyChange(options);
    expect(evidence.status).toBe('passed');
    expect(evidence.comparison?.remaining).toHaveLength(1);
});
it('marks targets missing in the base incomplete', async () => {
    baseAudit = audit();
    expect((await verifyChange(options)).status).toBe('incomplete');
});
it.each(['scan', 'install', 'timeout', 'mutation'])('%s errors never pass', async (error) => {
    fail = error;
    expect((await verifyChange(options)).status).toBe('incomplete');
});
it('records failing tests as failed, with output evidence', async () => {
    fail = 'tests';
    const evidence = await verifyChange(options);
    expect(evidence.status).toBe('failed');
    expect(evidence.exitCode).toBe(2);
    expect(evidence.checks.tests.stderr).toBe('assertion failed');
});
it('rejects malformed scanner output and persists incomplete evidence', async () => {
    headAudit = '{}';
    const evidence = await verifyChange(options);
    expect(evidence.exitCode).toBe(3);
    expect(evidence.reasons.join(' ')).toContain('unsupported');
});
it('does not pass when the candidate lacks the configured test script', async () => {
    fs.writeFileSync(path.join(repo, 'package.json'), '{"name":"fixture"}');
    git('add', 'package.json');
    git('commit', '--quiet', '-m', 'missing tests');
    options.head = git('rev-parse', 'HEAD');
    expect((await verifyChange(options)).reasons.join(' ')).toContain('no test');
});
it('rejects workspaces and symlinks as incomplete scope', async () => {
    fs.symlinkSync('/tmp', path.join(repo, 'link'));
    git('add', 'link');
    git('commit', '--quiet', '-m', 'unsupported symlink');
    options.head = git('rev-parse', 'HEAD');
    expect((await verifyChange(options)).reasons.join(' ')).toContain('regular files');
});
it('passes hostile-looking refs literally to Git and never executes them', async () => {
    options.base = '--help;touch SHOULD_NOT_EXIST';
    expect((await verifyChange(options)).status).toBe('incomplete');
    expect(fs.existsSync(path.join(repo, 'SHOULD_NOT_EXIST'))).toBe(false);
});
it('does not inherit private environment variables into scanners or tests', async () => {
    process.env.WARDEN_PRIVATE_FIXTURE = 'must-not-leak';
    try {
        await verifyChange(options);
        for (const call of mocked.mock.calls) {
            expect(call[2]?.env?.WARDEN_PRIVATE_FIXTURE).toBeUndefined();
        }
    } finally {
        delete process.env.WARDEN_PRIVATE_FIXTURE;
    }
});
it('defaults to restricted container test execution when requested', async () => {
    options.runner = 'docker';
    const evidence = await verifyChange(options);
    expect(evidence.status).toBe('passed');
    const commands = mocked.mock.calls.filter(([exe]) => exe === 'docker');
    const tests = commands.find(([, args]) => args?.includes('--network=none'))!;
    expect(tests[1]).toContain('--cap-drop=ALL');
    expect(tests[1]).toContain('--read-only');
    expect(tests[1]).toContain('HOME=/tmp');
    expect(commands.some(([, args]) => args?.[0] === 'rm')).toBe(true);
});
it('reports unavailable Docker as incomplete without falling back to host execution', async () => {
    options.runner = 'docker';
    fail = 'docker';
    expect((await verifyChange(options)).status).toBe('incomplete');
    expect(mocked.mock.calls.some(([exe, args]) => exe === 'npm' && args?.[0] === 'test')).toBe(
        false
    );
});
it('supports numeric source targets even when the report has GHSA URLs', async () => {
    options.advisories = ['42'];
    expect((await verifyChange(options)).status).toBe('passed');
});
it('preserves multiple advisories for one package', () => {
    expect(parseAudit(audit([{}, { id: 'GHSA-9999-8888-7777', source: 43 }]))).toHaveLength(2);
});
it('fails closed on inconsistent audit counts and malformed advisory records', () => {
    const malformed = JSON.parse(audit([{}]));
    malformed.metadata.vulnerabilities.total = 0;
    expect(() => parseAudit(JSON.stringify(malformed))).toThrow();
    expect(() => parseAudit('{"error":{"message":"unavailable"}}')).toThrow();
});
it('detects worsened findings without treating a package version as identity', () => {
    const baseFinding = { id: advisory, package: 'example', severity: 'low' };
    const changes = compareFindings(
        [baseFinding],
        [{ ...baseFinding, severity: 'high' }],
        [advisory],
        'high'
    );
    expect(changes.worsened).toHaveLength(1);
    expect(changes.regressions).toHaveLength(1);
});
it('rejects invalid commands/options before running repository code', async () => {
    await expect(verifyChange({ ...options, testCommand: [] })).rejects.toThrow('Invalid');
    expect(() => advisoryId('not-an-advisory')).toThrow();
});

it('rejects unanchored advisory cycles even alongside valid findings', () => {
    const report = JSON.parse(audit([{}]));
    report.vulnerabilities.cycle = { name: 'cycle', severity: 'high', via: ['cycle'] };
    report.metadata.vulnerabilities.total = 2;
    expect(() => parseAudit(JSON.stringify(report))).toThrow('coverage');
});
it('rejects lockfile and manifest mismatch', async () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
    manifest.dependencies = { example: '2.0.0' };
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(manifest));
    git('add', 'package.json');
    git('commit', '--quiet', '-m', 'mismatch');
    options.head = git('rev-parse', 'HEAD');
    expect((await verifyChange(options)).reasons.join(' ')).toContain('disagree');
});
it('rejects workspaces', async () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
    manifest.workspaces = ['packages/*'];
    fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(manifest));
    git('add', 'package.json');
    git('commit', '--quiet', '-m', 'workspace');
    options.head = git('rev-parse', 'HEAD');
    expect((await verifyChange(options)).reasons.join(' ')).toContain('single-package');
});

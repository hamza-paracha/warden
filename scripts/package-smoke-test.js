#!/usr/bin/env node
// Exercise the shipped CLI from an unrelated project, without network scanners.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-package-'));
try {
    const packed = JSON.parse(
        execFileSync('npm', ['pack', '--json', '--pack-destination', temp], {
            cwd: root,
            encoding: 'utf8',
        })
    )[0];
    execFileSync('tar', ['-xzf', path.join(temp, packed.filename), '-C', temp]);
    const installed = path.join(temp, 'package');
    fs.symlinkSync(path.join(root, 'node_modules'), path.join(installed, 'node_modules'), 'dir');
    const bin = path.join(temp, 'bin');
    const project = path.join(temp, 'target project');
    fs.mkdirSync(bin);
    fs.mkdirSync(project);
    fs.writeFileSync(
        path.join(project, 'package.json'),
        JSON.stringify({ name: 'smoke-project', version: '1.0.0' })
    );
    execFileSync('git', ['init', '--quiet', project]);
    const npm = path.join(bin, 'npm');
    const env = {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        GITHUB_TOKEN: '',
        SNYK_TOKEN: '',
    };
    const cli = path.join(installed, 'dist/index.js');
    const scan = (extra = []) =>
        spawnSync(
            process.execPath,
            [cli, 'scan', project, '--dry-run', '--scanner', 'npm-audit', '--json', ...extra],
            { cwd: temp, env, encoding: 'utf8', timeout: 30000 }
        );
    const setAudit = (data, code = 0) =>
        fs.writeFileSync(
            npm,
            `#!/usr/bin/env node\nconsole.log(${JSON.stringify(JSON.stringify(data))}); process.exit(${code});\n`,
            { mode: 0o755 }
        );
    setAudit(
        {
            vulnerabilities: {
                example: {
                    name: 'example',
                    severity: 'high',
                    range: '<2.0.0',
                    via: [{ source: 42, title: 'Example advisory' }],
                    fixAvailable: { name: 'example', version: '2.0.0' },
                },
            },
        },
        1
    );
    const result = scan();
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.scanResult.summary.high, 1);
    assert.equal(report.attemptedFixes, 1);
    assert.equal(report.appliedFixes, 0);
    for (const name of [
        'scan-results.json',
        'warden.sarif',
        'warden-report.md',
        'scan-results.html',
        'agent-run-record.json',
        'history.json',
        'memory.json',
    ]) {
        assert.ok(fs.existsSync(path.join(project, 'scan-results', name)), name);
    }
    const scanOnly = scan(['--scan-only']);
    assert.equal(scanOnly.status, 0, scanOnly.stderr);
    assert.equal(JSON.parse(scanOnly.stdout).attemptedFixes, 0);
    assert.equal(JSON.parse(scanOnly.stdout).dryRun, true);
    for (const args of [
        ['--max-fixes', '2oops'],
        ['--severity', 'urgent'],
        ['--scan-timeout', '0'],
    ]) {
        assert.notEqual(scan(args).status, 0, `must reject ${args.join(' ')}`);
    }
    const exportedPath = path.join(temp, 'exported.sarif');
    const exported = spawnSync(
        process.execPath,
        [
            cli,
            'export-sarif',
            '--input',
            path.join(project, 'scan-results/scan-results.json'),
            '--output',
            exportedPath,
        ],
        { cwd: temp, env, encoding: 'utf8' }
    );
    assert.equal(exported.status, 0, exported.stderr);
    assert.equal(JSON.parse(fs.readFileSync(exportedPath, 'utf8')).version, '2.1.0');
    assert.ok(
        !fs.existsSync(path.join(installed, 'scan-results')),
        'must not write scans into the installation'
    );
    assert.ok(
        !fs.existsSync(path.join(temp, 'scan-results')),
        'must not split reports across projects'
    );
    setAudit(
        {
            vulnerabilities: {
                critical: {
                    name: 'critical',
                    severity: 'critical',
                    range: '<2',
                    via: [],
                    fixAvailable: false,
                },
            },
        },
        1
    );
    const gated = scan(['--ci']);
    assert.equal(gated.status, 2, gated.stderr);
    assert.equal(JSON.parse(gated.stdout).policyDecision.shouldFailPipeline, true);
    assert.ok(fs.existsSync(path.join(project, 'scan-results', 'warden-approval-request.json')));
    setAudit({ vulnerabilities: {} });
    const clean = scan(['--ci']);
    assert.equal(clean.status, 0, clean.stderr);
    assert.equal(JSON.parse(clean.stdout).scanResult.summary.total, 0);
    setAudit({ error: { code: 'ENOLOCK', summary: 'A lockfile is required' } }, 1);
    const failure = scan();
    assert.notEqual(failure.status, 0);
    assert.match(failure.stderr, /lockfile is required/);
    assert.doesNotMatch(failure.stdout, /"scanResult"/);
    // Exercise the packaged verification command with an actual isolated Git export.
    const verifiedProject = path.join(temp, 'verification project');
    fs.mkdirSync(verifiedProject);
    const vgit = (...args) =>
        execFileSync('git', args, { cwd: verifiedProject, encoding: 'utf8' }).trim();
    vgit('init', '--quiet');
    vgit('config', 'user.name', 'Package Fixture');
    vgit('config', 'user.email', 'fixture@example.com');
    fs.writeFileSync(
        path.join(verifiedProject, 'package.json'),
        JSON.stringify({
            name: 'verify-fixture',
            version: '1.0.0',
            scripts: { test: 'node test.js' },
        })
    );
    fs.writeFileSync(
        path.join(verifiedProject, 'package-lock.json'),
        JSON.stringify({
            lockfileVersion: 3,
            packages: { '': { version: '1.0.0' } },
        })
    );
    fs.writeFileSync(path.join(verifiedProject, 'test.js'), 'process.exit(0);');
    vgit('add', '.');
    vgit('commit', '--quiet', '-m', 'base');
    const base = vgit('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(verifiedProject, 'test.js'), '// patched\nprocess.exit(0);');
    vgit('add', '.');
    vgit('commit', '--quiet', '-m', 'candidate');
    const head = vgit('rev-parse', 'HEAD');
    const auditFinding = {
        auditReportVersion: 2,
        vulnerabilities: {
            example: {
                name: 'example',
                severity: 'high',
                via: [
                    {
                        source: 42,
                        severity: 'high',
                        url: 'https://github.com/advisories/GHSA-abcd-1234-5678',
                    },
                ],
            },
        },
        metadata: { vulnerabilities: { total: 1 } },
    };
    const cleanAudit = {
        auditReportVersion: 2,
        vulnerabilities: {},
        metadata: { vulnerabilities: { total: 0 } },
    };
    fs.writeFileSync(
        npm,
        `#!/usr/bin/env node
const path = require('node:path');
const args = process.argv.slice(2);
if (args[0] === '--version') console.log('11.0.0');
else if (args[0] === 'audit') console.log(JSON.stringify(path.basename(process.cwd()) === 'base' ? ${JSON.stringify(auditFinding)} : ${JSON.stringify(cleanAudit)}));
else if (args[0] === 'ci' || args[0] === 'test') console.log('Fixture check passed');
else process.exit(2);
`,
        { mode: 0o755 }
    );
    const verification = spawnSync(
        process.execPath,
        [
            cli,
            'verify',
            verifiedProject,
            '--base',
            base,
            '--head',
            head,
            '--advisory',
            '42',
            '--test-command',
            '["npm","test"]',
            '--test-runner',
            'trusted-host',
            '--output',
            path.join(temp, 'verification evidence'),
            '--json',
        ],
        { cwd: verifiedProject, env, encoding: 'utf8', timeout: 30000 }
    );
    assert.equal(verification.status, 0, verification.stderr || verification.stdout);
    assert.equal(JSON.parse(verification.stdout).status, 'passed');
    assert.equal(vgit('status', '--porcelain'), '');
    assert.ok(fs.existsSync(path.join(temp, 'verification evidence/verification.md')));
    console.log(
        'Packaged CLI smoke test passed (scan, artifacts, scanner failure, dependency verification).'
    );
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

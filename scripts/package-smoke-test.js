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
    for (const args of [['--max-fixes', '2oops'], ['--severity', 'urgent'], ['--scan-timeout', '0']]) {
        assert.notEqual(scan(args).status, 0, `must reject ${args.join(' ')}`);
    }
    const exportedPath = path.join(temp, 'exported.sarif');
    const exported = spawnSync(process.execPath, [cli, 'export-sarif', '--input',
        path.join(project, 'scan-results/scan-results.json'), '--output', exportedPath],
        { cwd: temp, env, encoding: 'utf8' });
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
    console.log('Packaged CLI smoke test passed (scan, artifacts, scanner failure).');
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

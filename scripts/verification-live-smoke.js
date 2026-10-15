#!/usr/bin/env node
// Opt-in network smoke: create our own repository, patch lodash, and verify it.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-live-verify-'));
const repository = path.join(temporary, 'fixture repository');
fs.mkdirSync(repository);
const env = {
    PATH: process.env.PATH,
    HOME: temporary,
    CI: 'true',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: os.devNull,
    npm_config_cache: path.join(temporary, '.npm'),
    npm_config_userconfig: path.join(temporary, 'empty-user.npmrc'),
    npm_config_globalconfig: path.join(temporary, 'empty-global.npmrc'),
};
const command = (exe, args) =>
    execFileSync(exe, args, { cwd: repository, env, encoding: 'utf8', timeout: 120000 });
const git = (...args) => command('git', args).trim();
try {
    git('init', '--quiet');
    git('config', 'user.name', 'Warden Fixture');
    git('config', 'user.email', 'fixture@example.com');
    const latest = command('npm', [
        'view',
        'lodash',
        'version',
        '--registry=https://registry.npmjs.org',
    ]).trim();
    assert.match(latest, /^\d+\.\d+\.\d+$/);
    const manifest = {
        name: 'warden-verification-fixture',
        version: '1.0.0',
        private: true,
        scripts: { test: 'node test.js' },
        dependencies: { lodash: '4.17.4' },
    };
    fs.writeFileSync(
        path.join(repository, 'test.js'),
        'require("node:assert/strict").deepEqual(require("lodash").chunk([1,2,3],2), [[1,2],[3]]);\n'
    );
    const snapshot = (version, message) => {
        manifest.dependencies.lodash = version;
        fs.writeFileSync(path.join(repository, 'package.json'), JSON.stringify(manifest));
        command('npm', [
            'install',
            '--package-lock-only',
            '--ignore-scripts',
            '--no-audit',
            '--no-fund',
            '--registry=https://registry.npmjs.org',
        ]);
        git('add', '.');
        git('commit', '--quiet', '-m', message);
        return git('rev-parse', 'HEAD');
    };
    const base = snapshot('4.17.4', 'vulnerable fixture');
    const scan = spawnSync(
        'npm',
        [
            'audit',
            '--json',
            '--package-lock-only',
            '--ignore-scripts',
            '--registry=https://registry.npmjs.org',
        ],
        { cwd: repository, env, encoding: 'utf8', timeout: 120000 }
    );
    assert.ok([0, 1].includes(scan.status), scan.stderr);
    const data = JSON.parse(scan.stdout);
    const ids = Object.values(data.vulnerabilities)
        .flatMap((item) => item.via)
        .filter((item) => typeof item === 'object')
        .map((item) => item.url.match(/GHSA-[a-z0-9-]+/i)?.[0])
        .filter(Boolean);
    assert.ok(ids.length, 'Expected known advisories in the old fixture');
    const head = snapshot(latest, 'patched fixture');
    const status = git('status', '--porcelain');
    const output = path.join(temporary, 'evidence');
    const args = [
        path.join(root, 'dist/index.js'),
        'verify',
        repository,
        '--base',
        base,
        '--head',
        head,
        '--advisory',
        ...new Set(ids),
        '--test-command',
        '["npm","test"]',
        '--test-runner',
        'trusted-host',
        '--output',
        output,
        '--json',
    ];
    const run = spawnSync(process.execPath, args, {
        cwd: repository,
        env,
        encoding: 'utf8',
        timeout: 120000,
    });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const evidence = JSON.parse(run.stdout);
    assert.equal(evidence.status, 'passed');
    assert.equal(evidence.checks.tests.status, 'passed');
    assert.equal(evidence.comparison.remainingTargets.length, 0);
    assert.equal(git('status', '--porcelain'), status);
    assert.equal(git('rev-parse', 'HEAD'), head);
    console.log(
        `Live verification passed: lodash 4.17.4 -> ${latest}; ${evidence.targets.length} target advisories resolved; tests passed; checkout unchanged.`
    );
    // The container path is checked when an already running Docker daemon is available.
    const docker = spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], {
        env,
        encoding: 'utf8',
        timeout: 10000,
    });
    if (docker.status === 0 && process.env.WARDEN_LIVE_DOCKER === '1') {
        command('docker', ['pull', 'node:24-bookworm-slim']);
        const containerArgs = [...args];
        containerArgs[containerArgs.indexOf('trusted-host')] = 'docker';
        const container = spawnSync(process.execPath, containerArgs, {
            cwd: repository,
            env,
            encoding: 'utf8',
            timeout: 240000,
        });
        assert.equal(container.status, 0, container.stderr || container.stdout);
        assert.equal(JSON.parse(container.stdout).status, 'passed');
        console.log('Live Docker verification passed.');
    } else {
        console.log(
            'Live Docker execution skipped; set WARDEN_LIVE_DOCKER=1 with a running daemon to test it.'
        );
    }
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

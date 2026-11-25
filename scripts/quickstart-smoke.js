#!/usr/bin/env node
// Release gate (needs the npm registry): install the packed CLI into an empty prefix and run
// every command the homepage and README advertise, verbatim, from a clean project.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const pkg = require(path.join(root, 'package.json'));
const homepage = fs.readFileSync(path.join(root, 'website/index.html'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');

const decode = (s) =>
    s
        .replace(/<[^>]+>/g, '')
        .replace(/&quot;/g, '"')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .trim();
const fromHomepage = [...homepage.matchAll(/<code[^>]*>([\s\S]*?)<\/code>/g)].map((m) =>
    decode(m[1])
);
const fromReadme = [...readme.matchAll(/```(?:bash|text)\n([\s\S]*?)```/g)].flatMap((m) =>
    m[1].split('\n').map((line) => line.replace(/^\$ /, '').replace(/\s+#.*$/, ''))
);
const commands = [
    ...new Set([...fromHomepage, ...fromReadme].filter((c) => /^warden(\s|$)/.test(c))),
];

const ran = (r) => `${r.stdout}\n${r.stderr}`;
const verdicts = (r) => [...r.stdout.matchAll(/^(ALLOW|WARN|BLOCK) (\S+)/gm)];
const verdictOf = (r, name) => verdicts(r).find(([, , id]) => id.startsWith(`${name}@`))?.[1];
const recognized = (usage) => (r) => {
    assert.doesNotMatch(ran(r), /unknown command/i);
    assert.match(ran(r), usage);
};
// Every advertised command needs an explicit expectation, so new copy cannot ship untested.
const expectations = {
    'warden --version': (r) => {
        assert.equal(r.status, 0, ran(r));
        assert.equal(r.stdout.trim(), pkg.version);
    },
    'warden inspect express': (r) => {
        assert.ok([0, 2].includes(r.status), ran(r));
        assert.ok(verdictOf(r, 'express'), ran(r));
    },
    'warden inspect express lodash@^4': (r) => {
        assert.ok([0, 2].includes(r.status), ran(r));
        assert.ok(verdictOf(r, 'express') && verdictOf(r, 'lodash'), ran(r));
    },
    'warden guard "npm install reqeusts colros chalk@5"': (r) => {
        assert.equal(r.status, 2, ran(r));
        assert.equal(verdictOf(r, 'reqeusts'), 'BLOCK', ran(r));
        assert.equal(verdictOf(r, 'colros'), 'BLOCK', ran(r));
        assert.match(r.stdout, /Did you mean colors\?/);
        assert.match(verdictOf(r, 'chalk') ?? '', /ALLOW|WARN/, ran(r));
    },
    'warden review . --base main': (r) => assert.equal(r.status, 0, ran(r)),
    'warden review . --base origin/main': (r) => assert.equal(r.status, 0, ran(r)),
    'warden agent-setup claude devin': (r, project) => {
        assert.equal(r.status, 0, ran(r));
        for (const file of [
            '.mcp.json',
            '.claude/settings.json',
            '.devin/mcp_config.json',
            '.devin/hooks.v1.json',
        ])
            assert.ok(fs.existsSync(path.join(project, file)), file);
    },
    'warden agent-setup claude devin codex': (r) => {
        assert.equal(r.status, 0, ran(r));
        assert.match(r.stdout, /\[mcp_servers\.warden\]/);
    },
    // The homepage shows these as command names; they must exist and explain their options.
    'warden verify': recognized(/required option '--base <ref>'/),
    'warden attest': recognized(/Usage: warden attest[\s\S]*keygen[\s\S]*sign[\s\S]*check/),
};

const npmView = spawnSync('npm', ['view', `${pkg.name}@${pkg.version}`, 'version'], {
    encoding: 'utf8',
});
const published = npmView.status === 0 && npmView.stdout.trim() === pkg.version;
if (!published && !/E404/.test(npmView.stderr)) throw new Error(npmView.stderr);
for (const [name, text] of [
    ['website/index.html', homepage],
    ['README.md', readme],
]) {
    const labelled = /source-only/i.test(text);
    if (!published)
        assert.ok(
            labelled,
            `${pkg.name}@${pkg.version} is not on npm, so ${name} must label its commands source-only.`
        );
    else if (labelled)
        console.warn(
            `${pkg.name}@${pkg.version} is on npm; remove the source-only label from ${name}.`
        );
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-quickstart-'));
try {
    const packed = JSON.parse(
        execFileSync('npm', ['pack', '--json', '--pack-destination', temp], {
            cwd: root,
            encoding: 'utf8',
        })
    )[0];
    const prefix = path.join(temp, 'prefix');
    execFileSync(
        'npm',
        [
            'install',
            '--global',
            '--prefix',
            prefix,
            '--no-audit',
            '--no-fund',
            path.join(temp, packed.filename),
        ],
        { cwd: temp, stdio: 'inherit' }
    );
    const home = path.join(temp, 'home');
    const project = path.join(temp, 'clean project');
    const remote = path.join(temp, 'origin.git');
    fs.mkdirSync(home);
    fs.mkdirSync(project);
    const env = {
        PATH: `${path.join(prefix, 'bin')}${path.delimiter}${process.env.PATH}`,
        HOME: home,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: os.devNull,
    };
    const git = (...args) => execFileSync('git', args, { cwd: project, env, encoding: 'utf8' });
    git('init', '--quiet', '--initial-branch=main');
    git('config', 'user.name', 'Quickstart Fixture');
    git('config', 'user.email', 'fixture@example.com');
    fs.writeFileSync(
        path.join(project, 'package.json'),
        JSON.stringify({ name: 'quickstart-fixture', version: '1.0.0', private: true })
    );
    fs.writeFileSync(
        path.join(project, 'package-lock.json'),
        JSON.stringify({
            name: 'quickstart-fixture',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: { '': { name: 'quickstart-fixture', version: '1.0.0' } },
        })
    );
    git('add', '.');
    git('commit', '--quiet', '-m', 'base');
    execFileSync('git', ['init', '--quiet', '--bare', remote], { env });
    git('remote', 'add', 'origin', remote);
    git('push', '--quiet', 'origin', 'main');

    const installed = spawnSync('warden', ['--version'], { cwd: project, env, encoding: 'utf8' });
    assert.equal(installed.stdout.trim(), pkg.version, 'warden on PATH is the packed build');
    const missing = commands.filter((command) => !expectations[command]);
    assert.deepEqual(missing, [], 'Add an expectation for each advertised command');
    for (const command of commands) {
        const result = spawnSync('sh', ['-c', command], {
            cwd: project,
            env,
            encoding: 'utf8',
            timeout: 120000,
        });
        expectations[command](result, project);
        console.log(`ok  ${command}`);
    }
    console.log(
        `Quickstart smoke passed: ${commands.length} advertised commands against a clean install of ${packed.filename}${published ? '' : ' (source-only: this version is not on npm yet)'}.`
    );
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

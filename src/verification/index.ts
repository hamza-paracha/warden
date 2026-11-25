import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash, randomUUID } from 'crypto';
import { runProcess, ProcessError } from '../services/process';
import { writeJsonAtomic } from '../services/artifacts';
import {
    DependencyReview,
    policyFromConfigText,
    reviewLockfiles,
    SupplyChainPolicy,
} from '../supply-chain';
import { lockEntries } from '../supply-chain/lockfile';

export type Finding = { id: string; package: string; severity: string; aliases?: string[] };
export type Check = {
    command: string[];
    startedAt: string;
    durationMs?: number;
    exitCode?: number;
    status: 'passed' | 'failed' | 'incomplete';
    error?: string;
    stdout?: string;
    stderr?: string;
};
export interface VerifyOptions {
    repository: string;
    base: string;
    head: string;
    advisories: string[];
    testCommand: string[];
    runner: 'docker' | 'trusted-host';
    timeoutMs: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
    output: string;
    image?: string;
    /** Review newly installed releases for supply-chain risk (default true). */
    supplyChain?: boolean;
    supplyChainPolicy?: SupplyChainPolicy;
    /** Where reviewers can download the published evidence files, linked from verification.md. */
    evidenceUrl?: string;
}
export type DependencyChange = { name: string; from?: string; to?: string; direct: boolean };
export type Evidence = {
    schemaVersion: 1;
    startedAt: string;
    finishedAt?: string;
    status: 'passed' | 'failed' | 'incomplete';
    exitCode: number;
    reasons: string[];
    runner: string;
    severity?: string;
    testCommand?: string[];
    scanner: { name: string; version?: string; command: string[] };
    targets: string[];
    revisions: Record<
        string,
        { sha: string; lockfileSha256?: string; manifestSha256?: string; findings?: Finding[] }
    >;
    checks: Record<string, Check>;
    changedFiles?: string[];
    dependencyChanges?: DependencyChange[];
    comparison?: ReturnType<typeof compareFindings>;
    supplyChain?: DependencyReview;
};
const rank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const auditArgs = [
    'audit',
    '--json',
    '--package-lock-only',
    '--ignore-scripts',
    '--registry=https://registry.npmjs.org',
];
const hash = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');

export function advisoryId(value: string): string {
    const ghsa = value.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
    if (ghsa) return ghsa[0].toUpperCase();
    if (/^(?:npm:)?\d+$/.test(value)) return `npm:${value.replace(/^npm:/, '')}`;
    throw new Error(
        `Unsupported advisory ID: ${value}. Use a GHSA ID or numeric npm advisory source.`
    );
}

/** npm audit v2 can list multiple advisories per package. Preserve every one. */
export function parseAudit(raw: string): Finding[] {
    const report = JSON.parse(raw);
    if (
        report?.error ||
        report?.auditReportVersion !== 2 ||
        !report.vulnerabilities ||
        typeof report.vulnerabilities !== 'object' ||
        Array.isArray(report.vulnerabilities) ||
        !report.metadata?.vulnerabilities
    )
        throw new Error('Invalid or unsupported npm audit v2 report.');
    const results = new Map<string, Finding>();
    for (const [name, item] of Object.entries(report.vulnerabilities)) {
        const value = item as any;
        if (
            !value ||
            value.name !== name ||
            !Array.isArray(value.via) ||
            !value.via.length ||
            !['low', 'moderate', 'high', 'critical', 'info'].includes(value.severity)
        ) {
            throw new Error(`Incomplete audit coverage for ${name}.`);
        }
        for (const via of value.via) {
            if (typeof via === 'string') {
                if (!Object.prototype.hasOwnProperty.call(report.vulnerabilities, via)) {
                    throw new Error(`Missing advisory chain for ${name}.`);
                }
                continue;
            }
            if (
                !via ||
                !Number.isInteger(via.source) ||
                !via.url ||
                !['low', 'moderate', 'high', 'critical', 'info'].includes(via.severity)
            ) {
                throw new Error(`Malformed advisory for ${name}.`);
            }
            const id = advisoryId(/GHSA-/i.test(via.url) ? via.url : String(via.source));
            const severity =
                via.severity === 'moderate'
                    ? 'medium'
                    : via.severity === 'info'
                      ? 'low'
                      : via.severity;
            const key = `${name}|${id}`;
            if (!results.has(key) || rank[severity] > rank[results.get(key)!.severity]) {
                results.set(key, { id, package: name, severity, aliases: [`npm:${via.source}`] });
            }
        }
    }
    const anchored = (name: string, visited = new Set<string>()): boolean => {
        if (visited.has(name)) return false;
        visited.add(name);
        return report.vulnerabilities[name].via.some(
            (via: any) =>
                typeof via === 'object' ||
                (typeof via === 'string' && anchored(via, new Set(visited)))
        );
    };
    if (!Object.keys(report.vulnerabilities).every((name) => anchored(name))) {
        throw new Error('Advisory chain has no observed source; coverage is incomplete.');
    }
    const total = report.metadata.vulnerabilities.total;
    if (
        !Number.isInteger(total) ||
        total !== Object.keys(report.vulnerabilities).length ||
        (total > 0 && !results.size) ||
        (total === 0 && results.size > 0)
    )
        throw new Error('Audit summary and advisory coverage disagree.');
    return [...results.values()].sort((a, b) =>
        `${a.package}|${a.id}`.localeCompare(`${b.package}|${b.id}`)
    );
}

export function compareFindings(
    base: Finding[],
    head: Finding[],
    targets: string[],
    severity: string
) {
    const key = (f: Finding) => `${f.package}|${f.id}`;
    const previous = new Map(base.map((f) => [key(f), f]));
    const current = new Map(head.map((f) => [key(f), f]));
    const newFindings = head.filter((f) => !previous.has(key(f)));
    const worsened = head.filter(
        (f) => previous.has(key(f)) && rank[f.severity] > rank[previous.get(key(f))!.severity]
    );
    return {
        resolved: base.filter((f) => !current.has(key(f))),
        remaining: head.filter((f) => previous.has(key(f))),
        newFindings,
        worsened,
        missingTargets: targets.filter(
            (id) => !base.some((f) => f.id === id || f.aliases?.includes(id))
        ),
        remainingTargets: targets.filter((id) =>
            head.some((f) => f.id === id || f.aliases?.includes(id))
        ),
        regressions: [...newFindings, ...worsened].filter(
            (f) => rank[f.severity] >= rank[severity]
        ),
    };
}

function safeEnvironment(home: string): NodeJS.ProcessEnv {
    return {
        PATH: process.env.PATH,
        HOME: home,
        USERPROFILE: home,
        TMPDIR: home,
        LANG: 'C.UTF-8',
        CI: 'true',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: os.devNull,
        GIT_TERMINAL_PROMPT: '0',
        npm_config_userconfig: path.join(home, 'empty-user.npmrc'),
        npm_config_globalconfig: path.join(home, 'empty-global.npmrc'),
        npm_config_cache: path.join(home, '.npm'),
        npm_config_registry: 'https://registry.npmjs.org',
    };
}

/** Export only Git-tracked regular files, without touching the source index or checkout. */
async function snapshot(repo: string, sha: string, target: string, env: NodeJS.ProcessEnv) {
    const listing = await runProcess('git', ['ls-tree', '-rz', '--full-tree', sha], {
        cwd: repo,
        env,
        log: false,
    });
    const files: string[] = [];
    for (const entry of listing.stdout.split('\0').filter(Boolean)) {
        const tab = entry.indexOf('\t');
        const [mode, type] = entry.slice(0, tab).split(' ');
        const name = entry.slice(tab + 1);
        if (tab < 0 || !['100644', '100755'].includes(mode) || type !== 'blob') {
            throw new Error(
                'Verification currently supports regular files only; symlinks/submodules need manual review.'
            );
        }
        if (
            path.isAbsolute(name) ||
            name.split('/').some((p) => p === '..' || p === '.git') ||
            name.includes('\\')
        ) {
            throw new Error('Unsafe repository path.');
        }
        // Never export credentials, environment files, or repo-local npm configuration.
        if (
            name.split('/').some((p) => /^\.env(?:\.|$)|^\.npmrc$|secret|token|key|\.pem$/i.test(p))
        )
            continue;
        files.push(name);
    }
    if (!files.includes('package.json') || !files.includes('package-lock.json')) {
        throw new Error(
            'Both package.json and package-lock.json must be tracked in each revision.'
        );
    }
    if (files.length > 5000 || files.join('').length > 100000)
        throw new Error('Repository exceeds initial verification scope.');
    fs.mkdirSync(target);
    const archive = `${target}.tar`;
    await runProcess(
        'git',
        [
            '--literal-pathspecs',
            'archive',
            '--format=tar',
            `--output=${archive}`,
            sha,
            '--',
            ...files,
        ],
        { cwd: repo, env, log: false }
    );
    await runProcess('tar', ['-xf', archive, '-C', target], { env, log: false });
    const manifest = JSON.parse(fs.readFileSync(path.join(target, 'package.json'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(path.join(target, 'package-lock.json'), 'utf8'));
    if (
        manifest.workspaces ||
        ![2, 3].includes(lock.lockfileVersion) ||
        !lock.packages?.[''] ||
        Object.values(lock.packages).some((p: any) => p?.link)
    )
        throw new Error('Only single-package npm projects with v2/v3 lockfiles are supported.');
    for (const field of [
        'dependencies',
        'devDependencies',
        'optionalDependencies',
        'peerDependencies',
    ]) {
        const stable = (o: any) =>
            JSON.stringify(Object.entries(o || {}).sort(([a], [b]) => a.localeCompare(b)));
        if (stable(manifest[field]) !== stable(lock.packages[''][field]))
            throw new Error('Manifest and lockfile dependency declarations disagree.');
    }
    return manifest;
}

export async function verifyChange(options: VerifyOptions): Promise<Evidence> {
    if (
        !options.base ||
        !options.head ||
        !options.advisories.length ||
        !options.testCommand.length ||
        options.testCommand.some((a) => typeof a !== 'string' || a.includes('\0')) ||
        !options.testCommand[0] ||
        !['docker', 'trusted-host'].includes(options.runner) ||
        !rank[options.severity] ||
        !Number.isSafeInteger(options.timeoutMs) ||
        options.timeoutMs <= 0
    ) {
        throw new Error('Invalid verification options.');
    }
    const targets = [...new Set(options.advisories.map(advisoryId))];
    const output = path.resolve(options.output);
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-verify-'));
    const env = safeEnvironment(temp);
    const evidence: Evidence = {
        schemaVersion: 1,
        startedAt: new Date().toISOString(),
        status: 'incomplete',
        exitCode: 3,
        reasons: [],
        runner: options.runner,
        severity: options.severity,
        testCommand: options.testCommand,
        targets,
        revisions: {},
        checks: {},
        scanner: { name: 'npm-audit', command: ['npm', ...auditArgs] },
    };
    const execute = async (
        name: string,
        command: string[],
        cwd?: string,
        allowedExitCodes = [0]
    ) => {
        const check: Check = { command, startedAt: new Date().toISOString(), status: 'incomplete' };
        evidence.checks[name] = check;
        try {
            const result = await runProcess(command[0], command.slice(1), {
                cwd,
                env,
                timeout: options.timeoutMs,
                log: false,
                allowedExitCodes,
            });
            Object.assign(check, result, { status: result.exitCode === 0 ? 'passed' : 'failed' });
            return result;
        } catch (error) {
            check.error = error instanceof Error ? error.message : String(error);
            if (error instanceof ProcessError) {
                check.stdout = error.stdout;
                check.stderr = error.stderr;
                if (typeof error.code === 'number' && !error.killed && !error.signal) {
                    check.exitCode = error.code;
                    check.status = 'failed';
                }
            }
            throw error;
        }
    };
    try {
        evidence.scanner.version = (
            await execute('npmVersion', ['npm', '--version'])
        ).stdout.trim();
        for (const [label, ref] of [
            ['base', options.base],
            ['head', options.head],
        ]) {
            const sha = (
                await execute(
                    `${label}Revision`,
                    ['git', 'rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`],
                    options.repository
                )
            ).stdout.trim();
            if (!/^[a-f0-9]{40,64}$/.test(sha)) throw new Error('Invalid commit identity.');
            evidence.revisions[label] = { sha };
            const dir = path.join(temp, label);
            const manifest = await snapshot(options.repository, sha, dir, env);
            evidence.revisions[label].lockfileSha256 = hash(path.join(dir, 'package-lock.json'));
            evidence.revisions[label].manifestSha256 = hash(path.join(dir, 'package.json'));
            const audit = await execute(`${label}Audit`, ['npm', ...auditArgs], dir, [0, 1]);
            evidence.revisions[label].findings = parseAudit(audit.stdout);
            // Exit 1 means findings, not an operational scanner failure.
            evidence.checks[`${label}Audit`].status = 'passed';
            if (
                label === 'head' &&
                ['npm', 'npm.cmd'].includes(options.testCommand[0]) &&
                ['test', 'run'].includes(options.testCommand[1])
            ) {
                const script = options.testCommand[1] === 'test' ? 'test' : options.testCommand[2];
                if (!manifest.scripts?.[script])
                    throw new Error(`Candidate has no ${script || 'requested'} test script.`);
            }
        }
        evidence.changedFiles = (
            await execute(
                'changedFiles',
                [
                    'git',
                    'diff',
                    '--name-only',
                    '-z',
                    evidence.revisions.base.sha,
                    evidence.revisions.head.sha,
                    '--',
                ],
                options.repository
            )
        ).stdout
            .split('\0')
            .filter(Boolean);
        evidence.dependencyChanges = dependencyChanges(
            readLock(path.join(temp, 'base')),
            readLock(path.join(temp, 'head'))
        );
        evidence.comparison = compareFindings(
            evidence.revisions.base.findings!,
            evidence.revisions.head.findings!,
            targets,
            options.severity
        );
        if (evidence.comparison.missingTargets.length)
            throw new Error(
                'Requested advisory was not observed in the base; remediation is unverified.'
            );
        const dir = path.join(temp, 'head');
        let testsPassed = false;
        if (options.runner === 'docker') {
            const image = options.image || 'node:24-bookworm-slim';
            if (!/^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/.test(image))
                throw new Error('Invalid container image.');
            const inspected = await execute('containerImage', [
                'docker',
                'image',
                'inspect',
                '--format',
                '{{.Id}}',
                image,
            ]);
            const imageId = inspected.stdout.trim();
            if (!/^sha256:[a-f0-9]{64}$/.test(imageId))
                throw new Error('Cannot establish container image identity.');
            const container = `warden-verify-${randomUUID()}`;
            const common = [
                'docker',
                'run',
                '--rm',
                '--name',
                container,
                '--cap-drop=ALL',
                '--security-opt=no-new-privileges',
                '--memory=1g',
                '--cpus=2',
                '--pids-limit=256',
                '--read-only',
                '--tmpfs',
                '/tmp:rw,nosuid,size=256m',
                '--user',
                `${os.userInfo().uid}:${os.userInfo().gid}`,
                '--env',
                'HOME=/tmp',
                '--env',
                'CI=true',
                '--env',
                'npm_config_cache=/tmp/npm-cache',
                '--mount',
                `type=bind,src=${dir},dst=/workspace`,
                '--workdir',
                '/workspace',
            ];
            const containerCheck = async (name: string, command: string[], offline: boolean) => {
                try {
                    return await execute(name, [
                        ...common,
                        ...(offline ? ['--network=none'] : []),
                        imageId,
                        ...command,
                    ]);
                } finally {
                    await runProcess('docker', ['rm', '-f', container], {
                        env,
                        timeout: 10000,
                        log: false,
                        allowedExitCodes: [0, 1],
                    }).catch(() => undefined);
                }
            };
            await containerCheck(
                'install',
                [
                    'npm',
                    'ci',
                    '--ignore-scripts',
                    '--no-audit',
                    '--no-fund',
                    '--registry=https://registry.npmjs.org',
                ],
                false
            );
            try {
                await containerCheck('tests', options.testCommand, true);
                testsPassed = true;
            } catch (error) {
                if (evidence.checks.tests?.status !== 'failed') throw error;
            }
        } else {
            await execute(
                'install',
                ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
                dir
            );
            try {
                await execute('tests', options.testCommand, dir);
                testsPassed = true;
            } catch (error) {
                if (evidence.checks.tests?.status !== 'failed') throw error;
            }
        }
        // Installed files/test scripts must not silently replace the dependency snapshot being verified.
        if (
            hash(path.join(dir, 'package-lock.json')) !== evidence.revisions.head.lockfileSha256 ||
            hash(path.join(dir, 'package.json')) !== evidence.revisions.head.manifestSha256
        ) {
            throw new Error(
                'Candidate tests or installation changed dependency files; evidence is incomplete.'
            );
        }
        if (options.supplyChain !== false) {
            const read = (label: string, file: string) => {
                const target = path.join(temp, label, file);
                return fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : undefined;
            };
            // Policy comes from the base snapshot so a candidate cannot allowlist itself.
            evidence.supplyChain = await reviewLockfiles(
                JSON.parse(read('base', 'package-lock.json')!),
                JSON.parse(read('head', 'package-lock.json')!),
                {
                    policy:
                        options.supplyChainPolicy ??
                        policyFromConfigText(read('base', '.wardenrc.json')),
                }
            );
            if (evidence.supplyChain.status === 'incomplete')
                throw new Error(
                    `Supply-chain review incomplete: ${evidence.supplyChain.reasons.join(' ')}`
                );
        }
        const comparison = evidence.comparison;
        if (!testsPassed) evidence.reasons.push('Candidate tests failed.');
        if (comparison.remainingTargets.length)
            evidence.reasons.push('Target advisory remains in the candidate.');
        if (comparison.regressions.length)
            evidence.reasons.push('New or worsened findings exceed the severity threshold.');
        if (evidence.supplyChain?.status === 'failed')
            evidence.reasons.push(
                `Supply-chain review flagged newly installed releases: ${evidence.supplyChain.reasons.join(' ')}`
            );
        evidence.status = evidence.reasons.length ? 'failed' : 'passed';
        evidence.exitCode = evidence.status === 'passed' ? 0 : 2;
    } catch (error) {
        evidence.status = 'incomplete';
        evidence.exitCode = 3;
        evidence.reasons.push(error instanceof Error ? error.message : String(error));
    } finally {
        evidence.finishedAt = new Date().toISOString();
        try {
            writeJsonAtomic(path.join(output, 'verification.json'), evidence);
            writeJsonAtomic(path.join(output, 'verification-summary.json'), {
                status: evidence.status,
                reasons: evidence.reasons,
                targets: evidence.targets,
                base: evidence.revisions.base?.sha,
                head: evidence.revisions.head?.sha,
                dependencyChanges: evidence.dependencyChanges,
                tests: evidence.checks.tests?.status ?? 'not run',
            });
            const md = formatVerificationMarkdown(evidence, { evidenceUrl: options.evidenceUrl });
            const pending = path.join(output, `.verification-${randomUUID()}.tmp`);
            try {
                fs.writeFileSync(pending, md);
                fs.renameSync(pending, path.join(output, 'verification.md'));
            } finally {
                fs.rmSync(pending, { force: true });
            }
        } finally {
            fs.rmSync(temp, { recursive: true, force: true });
        }
    }
    return evidence;
}

const readLock = (dir: string) =>
    JSON.parse(fs.readFileSync(path.join(dir, 'package-lock.json'), 'utf8'));

/** Installed package versions that differ between two lockfiles, direct dependencies first. */
export function dependencyChanges(baseLock: any, headLock: any): DependencyChange[] {
    const declared = new Set(
        [baseLock, headLock].flatMap((lock) =>
            ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap(
                (field) => Object.keys(lock.packages?.['']?.[field] ?? {})
            )
        )
    );
    const base = new Map(lockEntries(baseLock).map((e) => [e.path, e]));
    const head = new Map(lockEntries(headLock).map((e) => [e.path, e]));
    const rows = new Map<string, DependencyChange>();
    for (const location of new Set([...base.keys(), ...head.keys()])) {
        const from = base.get(location);
        const to = head.get(location);
        if (from?.version === to?.version && from?.name === to?.name) continue;
        const name = (to ?? from)!.name;
        const row = {
            name,
            from: from?.version,
            to: to?.version,
            direct: declared.has(name) && location === `node_modules/${name}`,
        };
        const key = `${name}|${row.from}|${row.to}`;
        rows.set(key, { ...row, direct: row.direct || Boolean(rows.get(key)?.direct) });
    }
    return [...rows.values()].sort(
        (a, b) => Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name)
    );
}

const cell = (value: unknown) =>
    String(value)
        .replace(/[\r\n]+/g, ' ')
        .replace(/\|/g, '\\|');
const MAX_ROWS = 25;

/** Describe only the install and test steps the evidence records as having run. */
function executionLimitation({ checks: { install, tests }, runner }: Evidence): string {
    const docker = runner === 'docker';
    if (!install)
        return '- Verification stopped before dependencies were installed; tests did not run.';
    if (install.status !== 'passed')
        return `- Dependency installation did not complete (${install.status}); tests did not run.`;
    const installed = `- Dependencies were installed with \`--ignore-scripts\``;
    if (!tests)
        return `${installed} ${docker ? 'in a resource-limited container' : 'directly on the host (`trusted-host`)'}; tests did not run.`;
    if (tests.status === 'incomplete')
        return `${installed}; tests were started ${docker ? 'offline in a resource-limited container' : 'directly on the host (`trusted-host`) without container isolation'} but did not finish.`;
    return docker
        ? `${installed}; tests ran offline in a resource-limited container.`
        : `${installed}; tests ran directly on the host (\`trusted-host\`) without container isolation.`;
}

/** Reviewer summary for a pull request: what changed, what was checked, and what was not. */
export function formatVerificationMarkdown(
    evidence: Evidence,
    options: { evidenceUrl?: string } = {}
): string {
    const { comparison, checks, supplyChain } = evidence;
    const severity = evidence.severity ?? 'high';
    const tests = checks.tests;
    const testCommand = evidence.testCommand ?? tests?.command ?? [];
    const headline = {
        passed: `Every target advisory is gone from the candidate, no new or worsened findings reached ${severity}, and the candidate's tests passed.`,
        failed: 'The checks ran, and the candidate does not meet the bar. See **Why** below.',
        incomplete:
            "Warden could not finish verifying this patch, so it is **unverified**. Don't treat this as a pass; see **What stopped it** below.",
    }[evidence.status];
    const lines = [
        '# Warden dependency verification',
        '',
        `**Result: ${evidence.status.toUpperCase()}**. ${headline}`,
        '',
        `- Base: \`${evidence.revisions.base?.sha || 'unresolved'}\``,
        `- Candidate: \`${evidence.revisions.head?.sha || 'unresolved'}\``,
        `- Runner: ${evidence.runner}`,
        '',
        '## Dependency changes',
        '',
    ];
    const changes = evidence.dependencyChanges;
    if (!changes) lines.push('Not compared: verification stopped before the lockfiles were read.');
    else if (!changes.length) lines.push('No installed package versions changed.');
    else {
        lines.push('| Package | Base | Candidate | Scope |', '| --- | --- | --- | --- |');
        for (const c of changes.slice(0, MAX_ROWS))
            lines.push(
                `| ${cell(c.name)} | ${cell(c.from ?? 'not installed')} | ${cell(c.to ?? 'removed')} | ${c.direct ? 'direct' : 'transitive'} |`
            );
        if (changes.length > MAX_ROWS)
            lines.push(
                '',
                `${changes.length - MAX_ROWS} more changes are listed in verification.json.`
            );
    }
    lines.push(
        '',
        '## Target advisories',
        '',
        '| Advisory | Package | Base | Candidate |',
        '| --- | --- | --- | --- |'
    );
    for (const id of evidence.targets) {
        const match = (f: Finding) => f.id === id || f.aliases?.includes(id);
        const found = evidence.revisions.base?.findings?.find(match);
        const [inBase, inHead] = !comparison
            ? ['unknown', 'unknown']
            : comparison.missingTargets.includes(id)
              ? ['not found', 'not verifiable']
              : [
                    `present (${found?.severity})`,
                    comparison.remainingTargets.includes(id) ? 'still present' : 'resolved',
                ];
        lines.push(`| ${cell(id)} | ${cell(found?.package ?? '-')} | ${inBase} | ${inHead} |`);
    }
    lines.push(
        '',
        '## Tests',
        '',
        tests
            ? `\`${cell(testCommand.join(' '))}\` on ${evidence.runner}: **${tests.status}**${tests.exitCode !== undefined ? ` (exit ${tests.exitCode})` : ''}${tests.durationMs !== undefined ? ` in ${(tests.durationMs / 1000).toFixed(1)}s` : ''}`
            : `\`${cell(testCommand.join(' '))}\`: **not run**`,
        '',
        '## Other findings',
        '',
        `- New findings: ${comparison?.newFindings.length ?? 'unknown'}`,
        `- Worsened findings: ${comparison?.worsened.length ?? 'unknown'}`,
        `- New or worsened at ${severity} or above: ${comparison?.regressions.length ?? 'unknown'}`,
        `- Resolved findings: ${comparison?.resolved.length ?? 'unknown'}`,
        `- Supply-chain review: ${supplyChain ? `${supplyChain.status} (${supplyChain.summary.reviewed} releases, ${supplyChain.summary.blocked} blocked, ${supplyChain.summary.warned} warned)` : 'not run'}`
    );
    if (evidence.reasons.length)
        lines.push(
            '',
            evidence.status === 'incomplete' ? '## What stopped it' : '## Why',
            '',
            ...evidence.reasons.map((reason) => `- ${cell(reason)}`)
        );
    lines.push(
        '',
        '## Limitations',
        '',
        `- Advisory status comes from \`npm audit\`${evidence.scanner.version ? ` (npm ${evidence.scanner.version})` : ''} against the public npm registry at ${evidence.finishedAt ?? evidence.startedAt}. Advisories published later, or missing from that database, are not covered.`,
        '- Tests only show what the test command exercises. Passing tests do not prove the application behaves the same.',
        executionLimitation(evidence),
        ...(supplyChain ? [] : ['- The behavior review of newly installed releases did not run.']),
        '- Scope is single-package npm projects. This result covers the configured checks; it does not certify that the application is secure.',
        '',
        '## Evidence',
        '',
        ...(options.evidenceUrl ? [`- Published evidence: ${options.evidenceUrl}`] : []),
        '- `verification.json`: every command, exit code, output, timestamp, commit SHA, and lockfile hash.',
        '- `verification-summary.json`: the result in machine-readable form.',
        ''
    );
    return lines.join('\n');
}

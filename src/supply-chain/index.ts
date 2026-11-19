import { createHash } from 'crypto';
import { runProcess } from '../services/process';
import { diffLockfiles, LockEntry } from './lockfile';
import {
    isAllowed,
    loadSupplyChainPolicy,
    normalizePolicy,
    policyFromConfigText,
    SupplyChainPolicy,
} from './policy';
import {
    createRegistryClient,
    PackageNotFoundError,
    Packument,
    PackumentVersion,
    previousVersion,
    RegistryClient,
    resolveVersion,
    validPackageName,
} from './registry';
import {
    diffPackages,
    installScripts,
    parseManifest,
    RISK_RANK,
    RiskSeverity,
    scriptSignals,
    Signal,
} from './signals';
import { PackageFiles } from './tarball';
import { typosquatTarget } from './typosquat';

export * from './policy';
export * from './signals';
export * from './lockfile';
export * from './typosquat';
export { createRegistryClient, resolveVersion, previousVersion } from './registry';
export type { RegistryClient, Packument, PackumentVersion } from './registry';

export type Verdict = 'allow' | 'warn' | 'block';

export interface PackageAssessment {
    name: string;
    requested?: string;
    version?: string;
    comparedWith?: string;
    verdict: Verdict;
    severity?: RiskSeverity;
    allowlisted: boolean;
    signals: Signal[];
    publishedAt?: string;
    ageHours?: number;
    publisher?: string;
    provenance?: boolean;
    weeklyDownloads?: number;
    diff?: {
        filesAdded: number;
        filesRemoved: number;
        filesChanged: number;
        unpackedBytesBefore: number;
        unpackedBytesAfter: number;
    };
    /** Evidence that could not be collected; reviews treat this as incomplete. */
    errors: string[];
}

export interface AssessOptions {
    policy?: SupplyChainPolicy;
    client?: RegistryClient;
    /** Compare against this version instead of the previous published release. */
    from?: string;
    /** Integrity the lockfile expects, checked against registry metadata. */
    expectedIntegrity?: string;
    now?: Date;
}

const DOWNGRADE: Record<RiskSeverity, RiskSeverity> = {
    critical: 'high',
    high: 'medium',
    medium: 'low',
    low: 'low',
};

export function highestSeverity(signals: Signal[]): RiskSeverity | undefined {
    return signals.reduce<RiskSeverity | undefined>(
        (max, s) => (!max || RISK_RANK[s.severity] > RISK_RANK[max] ? s.severity : max),
        undefined
    );
}

export function verdictFor(signals: Signal[], policy: SupplyChainPolicy): Verdict {
    const severity = highestSeverity(signals);
    if (!severity) return 'allow';
    if (RISK_RANK[severity] >= RISK_RANK[policy.blockAt]) return 'block';
    return RISK_RANK[severity] >= RISK_RANK.medium ? 'warn' : 'allow';
}

/** Split `name@spec`, keeping the scope separator of `@scope/name`. */
export function parsePackageSpec(spec: string): { name: string; range?: string } {
    const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
    return at > 0
        ? { name: spec.slice(0, at), range: spec.slice(at + 1) || undefined }
        : { name: spec };
}

function publishers(packument: Packument, before: string, limit = 10): Set<string> {
    const cutoff = packument.time?.[before];
    return new Set(
        Object.keys(packument.versions)
            .filter((v) => v !== before && (!cutoff || (packument.time?.[v] ?? '') < cutoff))
            .sort((a, b) => (packument.time?.[b] ?? '').localeCompare(packument.time?.[a] ?? ''))
            .slice(0, limit)
            .map((v) => packument.versions[v]?._npmUser?.name)
            .filter((n): n is string => Boolean(n))
    );
}

/** Detect registry metadata that disagrees with the package.json actually shipped. */
function manifestSignals(meta: PackumentVersion, files: PackageFiles): Signal[] {
    const shipped = parseManifest(files);
    if (!shipped) {
        return [
            {
                id: 'manifest-missing',
                severity: 'high',
                message: 'The tarball has no readable package.json',
            },
        ];
    }
    const signals: Signal[] = [];
    if (shipped.name !== meta.name || shipped.version !== meta.version)
        signals.push({
            id: 'manifest-mismatch',
            severity: 'high',
            message: 'Tarball package.json name/version differs from registry metadata',
            evidence: `${shipped.name}@${shipped.version}`,
        });
    const declared = installScripts(meta);
    const actual = installScripts(shipped);
    // npm adds an implicit node-gyp install script to metadata when binding.gyp exists.
    if (declared.install === 'node-gyp rebuild' && !actual.install && files.has('binding.gyp'))
        delete declared.install;
    const hidden = Object.keys(actual).filter((script) => declared[script] !== actual[script]);
    if (hidden.length)
        signals.push({
            id: 'manifest-mismatch',
            severity: 'critical',
            message: `Tarball lifecycle scripts differ from registry metadata (${hidden.join(', ')})`,
            file: 'package.json',
        });
    return signals;
}

export async function assessPackage(
    name: string,
    requested?: string,
    options: AssessOptions = {}
): Promise<PackageAssessment> {
    const policy = options.policy ?? loadSupplyChainPolicy();
    const client = options.client ?? createRegistryClient(policy.registry, policy.timeoutMs);
    const now = options.now ?? new Date();
    const result: PackageAssessment = {
        name,
        requested,
        verdict: 'allow',
        allowlisted: false,
        signals: [],
        errors: [],
    };
    const finish = () => {
        const exfiltration =
            result.signals.some((s) => s.id === 'network') &&
            result.signals.some((s) => s.id === 'credential-access' || s.id === 'env-harvest');
        if (exfiltration)
            result.signals.unshift({
                id: 'exfiltration-pattern',
                severity: 'critical',
                message:
                    'Newly reads credentials or environment data and opens network connections',
            });
        result.signals.sort((a, b) => RISK_RANK[b.severity] - RISK_RANK[a.severity]);
        result.severity = highestSeverity(result.signals);
        result.allowlisted = isAllowed(policy, name, result.version);
        result.verdict = result.allowlisted ? 'allow' : verdictFor(result.signals, policy);
        return result;
    };
    if (!validPackageName(name)) {
        result.signals.push({
            id: 'invalid-name',
            severity: 'critical',
            message: `"${name}" is not a valid npm package name`,
        });
        return finish();
    }
    let packument: Packument;
    try {
        packument = await client.packument(name);
    } catch (error) {
        if (!(error instanceof PackageNotFoundError)) {
            result.errors.push(error instanceof Error ? error.message : String(error));
            return finish();
        }
        const similar = typosquatTarget(name);
        result.signals.push({
            id: 'nonexistent',
            severity: 'critical',
            message:
                `${name} does not exist on the registry. Coding agents often invent package names, ` +
                `and attackers register them later (slopsquatting).` +
                (similar ? ` Did you mean ${similar}?` : ''),
        });
        return finish();
    }
    const version = resolveVersion(packument, requested);
    if (!version) {
        result.signals.push({
            id: 'unknown-version',
            severity: 'high',
            message: `No published version of ${name} matches "${requested}"`,
        });
        return finish();
    }
    result.version = version;
    const meta = packument.versions[version];
    result.publishedAt = packument.time?.[version];
    result.publisher = meta._npmUser?.name;
    result.provenance = Boolean(meta.dist?.attestations);
    if (options.expectedIntegrity && meta.dist?.integrity !== options.expectedIntegrity)
        result.signals.push({
            id: 'lockfile-integrity-mismatch',
            severity: 'critical',
            message: 'The lockfile integrity hash does not match the registry',
            evidence: `${options.expectedIntegrity.slice(0, 24)}…`,
        });
    if (result.publishedAt) {
        result.ageHours = Math.max(0, (now.getTime() - Date.parse(result.publishedAt)) / 36e5);
        if (result.ageHours < policy.minReleaseAgeHours)
            result.signals.push({
                id: 'fresh-release',
                severity: 'high',
                message:
                    `Published ${result.ageHours.toFixed(1)}h ago (policy minimum ${policy.minReleaseAgeHours}h). ` +
                    'Compromised releases are usually detected and pulled within the first day.',
            });
    }
    const created = packument.time?.created;
    if (created && now.getTime() - Date.parse(created) < 7 * 864e5)
        result.signals.push({
            id: 'new-package',
            severity: 'medium',
            message: `The package was first published ${created.slice(0, 10)}`,
        });
    if (meta.deprecated)
        result.signals.push({
            id: 'deprecated',
            severity: 'low',
            message: `Deprecated: ${String(meta.deprecated).slice(0, 160)}`,
        });
    const similar = typosquatTarget(name);
    if (similar) {
        result.weeklyDownloads = await client.weeklyDownloads(name);
        if ((result.weeklyDownloads ?? 0) < policy.establishedDownloads)
            result.signals.push({
                id: 'typosquat',
                severity: 'high',
                message: `Name resembles the popular package ${similar}${
                    result.weeklyDownloads === undefined
                        ? ''
                        : ` (${result.weeklyDownloads} weekly downloads)`
                }`,
            });
    }
    const baseline =
        options.from && options.from !== version && packument.versions[options.from]
            ? options.from
            : options.from === version
              ? undefined
              : previousVersion(packument, version);
    result.comparedWith = baseline;
    const before = baseline ? packument.versions[baseline] : undefined;
    if (before?.dist?.attestations && !result.provenance)
        result.signals.push({
            id: 'provenance-dropped',
            severity: 'high',
            message: `${baseline} was published with provenance; ${version} was not`,
        });
    const known = baseline ? publishers(packument, version) : new Set<string>();
    // Old maintainer handoffs are history; a new publisher matters during the attack window.
    if (result.publisher && known.size && !known.has(result.publisher))
        result.signals.push({
            id: 'new-publisher',
            severity: result.ageHours !== undefined && result.ageHours < 30 * 24 ? 'medium' : 'low',
            message: `Published by ${result.publisher}, who did not publish recent releases (${[...known].join(', ')})`,
        });
    const scripts = scriptSignals(before, meta);
    result.signals.push(
        ...(before ? scripts : scripts.map((s) => ({ ...s, severity: DOWNGRADE[s.severity] })))
    );
    if (!policy.diff || options.from === version) return finish();
    try {
        const [after, previous] = await Promise.all([
            client.tarball(meta),
            before ? client.tarball(before) : Promise.resolve(undefined),
        ]);
        const diff = diffPackages(previous, after);
        result.diff = {
            filesAdded: diff.filesAdded.length,
            filesRemoved: diff.filesRemoved.length,
            filesChanged: diff.filesChanged.length,
            unpackedBytesBefore: diff.unpackedBytesBefore,
            unpackedBytesAfter: diff.unpackedBytesAfter,
        };
        result.signals.push(...manifestSignals(meta, after));
        // Without an earlier release, capabilities are baseline behavior rather than a change.
        result.signals.push(
            ...(previous
                ? diff.signals
                : diff.signals.map((s) => ({ ...s, severity: DOWNGRADE[s.severity] })))
        );
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (/integrity/i.test(message))
            result.signals.push({ id: 'integrity-failure', severity: 'critical', message });
        else result.errors.push(`Content diff unavailable: ${message}`);
    }
    return finish();
}

async function pool<T, R>(items: T[], size: number, work: (item: T) => Promise<R>): Promise<R[]> {
    const results: R[] = new Array(items.length);
    let next = 0;
    await Promise.all(
        Array.from({ length: Math.min(size, items.length) }, async () => {
            while (next < items.length) {
                const index = next++;
                results[index] = await work(items[index]);
            }
        })
    );
    return results;
}

export interface DependencyReview {
    schemaVersion: 1;
    kind: 'dependency-review';
    startedAt: string;
    finishedAt?: string;
    status: 'passed' | 'failed' | 'incomplete';
    exitCode: number;
    reasons: string[];
    policy: SupplyChainPolicy;
    revisions?: Record<string, { sha: string; lockfileSha256: string }>;
    summary: {
        added: number;
        updated: number;
        removed: number;
        reviewed: number;
        blocked: number;
        warned: number;
    };
    lockfileSignals: Array<Signal & { package: string }>;
    packages: PackageAssessment[];
}

/** Assess every package version a lockfile change would newly install. */
export async function reviewLockfiles(
    baseLock: any,
    headLock: any,
    options: { policy?: SupplyChainPolicy; client?: RegistryClient; now?: Date } = {}
): Promise<DependencyReview> {
    const policy = options.policy ?? loadSupplyChainPolicy();
    const client = options.client ?? createRegistryClient(policy.registry, policy.timeoutMs);
    const review: DependencyReview = {
        schemaVersion: 1,
        kind: 'dependency-review',
        startedAt: new Date().toISOString(),
        status: 'incomplete',
        exitCode: 3,
        reasons: [],
        policy,
        summary: { added: 0, updated: 0, removed: 0, reviewed: 0, blocked: 0, warned: 0 },
        lockfileSignals: [],
        packages: [],
    };
    const change = diffLockfiles(baseLock, headLock, policy.registry);
    review.summary.added = change.added.length;
    review.summary.updated = change.updated.length;
    review.summary.removed = change.removed.length;
    review.lockfileSignals = change.signals.filter(
        (s) =>
            !isAllowed(
                policy,
                s.package.slice(0, s.package.lastIndexOf('@')),
                s.package.slice(s.package.lastIndexOf('@') + 1)
            )
    );
    const targets: Array<{ entry: LockEntry; from?: string }> = [
        ...change.updated.map(({ from, to }) => ({ entry: to, from: from.version })),
        ...change.added.map((entry) => ({ entry })),
    ].filter(({ entry }) => !entry.resolved || entry.resolved.startsWith(policy.registry));
    if (targets.length > policy.maxPackages) {
        review.reasons.push(
            `${targets.length} changed packages exceed supplyChain.maxPackages (${policy.maxPackages}); review is incomplete.`
        );
    }
    review.packages = await pool(
        targets.slice(0, policy.maxPackages),
        policy.concurrency,
        ({ entry, from }) =>
            assessPackage(entry.name, entry.version, {
                policy,
                client,
                from,
                expectedIntegrity: entry.integrity,
                now: options.now,
            })
    );
    review.summary.reviewed = review.packages.length;
    review.summary.blocked = review.packages.filter((p) => p.verdict === 'block').length;
    review.summary.warned = review.packages.filter((p) => p.verdict === 'warn').length;
    const lockBlocked = verdictFor(review.lockfileSignals, policy) === 'block';
    const errors = review.packages.filter((p) => p.errors.length);
    for (const item of errors)
        review.reasons.push(
            `${item.name}@${item.version ?? item.requested}: ${item.errors.join('; ')}`
        );
    if (review.summary.blocked)
        review.reasons.push(
            `Blocked: ${review.packages
                .filter((p) => p.verdict === 'block')
                .map((p) => `${p.name}@${p.version ?? p.requested}`)
                .join(', ')}`
        );
    if (lockBlocked) review.reasons.push('Lockfile changes exceed the supply-chain policy.');
    if (review.summary.blocked || lockBlocked) {
        review.status = 'failed';
        review.exitCode = 2;
    } else if (errors.length || targets.length > policy.maxPackages) {
        review.status = 'incomplete';
        review.exitCode = 3;
    } else {
        review.status = 'passed';
        review.exitCode = 0;
    }
    review.finishedAt = new Date().toISOString();
    return review;
}

/** Review the lockfile change between two Git revisions without checking anything out. */
export async function reviewDependencyChange(options: {
    repository: string;
    base: string;
    head: string;
    lockfile?: string;
    policy?: SupplyChainPolicy;
    /** Applied on top of the base revision's policy. */
    overrides?: Partial<SupplyChainPolicy>;
    client?: RegistryClient;
}): Promise<DependencyReview> {
    const lockfile = options.lockfile ?? 'package-lock.json';
    if (lockfile.startsWith('/') || lockfile.split('/').includes('..'))
        throw new Error('Lockfile must be a repository-relative path.');
    const revisions: Record<string, { sha: string; lockfileSha256: string }> = {};
    const locks: Record<string, any> = {};
    for (const [label, ref] of [
        ['base', options.base],
        ['head', options.head],
    ]) {
        const sha = (
            await runProcess(
                'git',
                ['rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`],
                {
                    cwd: options.repository,
                    log: false,
                }
            )
        ).stdout.trim();
        const raw = (
            await runProcess('git', ['show', `${sha}:${lockfile}`], {
                cwd: options.repository,
                log: false,
                maxBuffer: 256 * 1024 * 1024,
            })
        ).stdout;
        revisions[label] = { sha, lockfileSha256: createHash('sha256').update(raw).digest('hex') };
        locks[label] = JSON.parse(raw);
    }
    // The candidate must not be able to relax its own review, so policy comes from the base.
    const baseConfig = await runProcess('git', ['show', `${revisions.base.sha}:.wardenrc.json`], {
        cwd: options.repository,
        log: false,
    }).then(
        (result) => result.stdout,
        () => undefined
    );
    const review = await reviewLockfiles(locks.base, locks.head, {
        policy:
            options.policy ??
            normalizePolicy({
                ...policyFromConfigText(baseConfig),
                ...Object.fromEntries(
                    Object.entries(options.overrides ?? {}).filter(([, v]) => v !== undefined)
                ),
            }),
        client: options.client,
    });
    review.revisions = revisions;
    return review;
}

const ICON: Record<Verdict, string> = { allow: 'ALLOW', warn: 'WARN', block: 'BLOCK' };

export function formatAssessment(assessment: PackageAssessment): string {
    const id = `${assessment.name}@${assessment.version ?? assessment.requested ?? 'latest'}`;
    const facts = [
        assessment.publishedAt && `published ${assessment.publishedAt.slice(0, 10)}`,
        assessment.publisher && `by ${assessment.publisher}`,
        assessment.provenance !== undefined &&
            (assessment.provenance ? 'with provenance' : 'no provenance'),
        assessment.comparedWith && `diffed against ${assessment.comparedWith}`,
    ].filter(Boolean);
    return [
        `${ICON[assessment.verdict]} ${id}${facts.length ? ` (${facts.join(', ')})` : ''}${
            assessment.allowlisted ? ' [allowlisted]' : ''
        }`,
        ...assessment.signals.map(
            (s) =>
                `  - [${s.severity}] ${s.message}${s.file ? ` (${s.file})` : ''}${
                    s.evidence ? `\n      ${s.evidence}` : ''
                }`
        ),
        ...assessment.errors.map((e) => `  - [incomplete] ${e}`),
    ].join('\n');
}

export function formatReviewMarkdown(review: DependencyReview): string {
    const flagged = review.packages.filter((p) => p.verdict !== 'allow' || p.errors.length);
    const lines = [
        '# Warden dependency behavior review',
        '',
        `**Result: ${review.status.toUpperCase()}**`,
        '',
        ...(review.revisions
            ? [`- Base: ${review.revisions.base.sha}`, `- Candidate: ${review.revisions.head.sha}`]
            : []),
        `- Packages added: ${review.summary.added}, updated: ${review.summary.updated}, removed: ${review.summary.removed}`,
        `- Releases reviewed: ${review.summary.reviewed} (blocked ${review.summary.blocked}, warned ${review.summary.warned})`,
        `- Policy: block at ${review.policy.blockAt}, minimum release age ${review.policy.minReleaseAgeHours}h, content diff ${review.policy.diff ? 'on' : 'off'}`,
        '',
        ...review.reasons.map((r) => `- ${r.replace(/[\r\n]/g, ' ')}`),
    ];
    if (review.lockfileSignals.length) {
        lines.push('', '## Lockfile signals', '');
        for (const s of review.lockfileSignals)
            lines.push(
                `- **${s.severity}** \`${s.package}\`: ${s.message}${s.evidence ? ` — \`${s.evidence}\`` : ''}`
            );
    }
    if (flagged.length) {
        lines.push('', '## Flagged releases', '');
        for (const p of flagged) lines.push('```text', formatAssessment(p), '```');
    }
    lines.push(
        '',
        'Signals describe behavior a release adds relative to its predecessor. They are review prompts, not malware verdicts.',
        ''
    );
    return lines.join('\n');
}

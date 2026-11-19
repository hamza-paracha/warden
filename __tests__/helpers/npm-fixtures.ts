import { createHash } from 'crypto';
import { gzipSync } from 'zlib';
import type { Packument, PackumentVersion, RegistryClient } from '../../src/supply-chain';
import { PackageNotFoundError } from '../../src/supply-chain/registry';
import { readPackageTarball } from '../../src/supply-chain/tarball';

function header(name: string, size: number, type = '0'): Buffer {
    const block = Buffer.alloc(512);
    block.write(name.slice(0, 100), 0);
    block.write('0000644\0', 100);
    block.write('0000000\0', 108);
    block.write('0000000\0', 116);
    block.write(size.toString(8).padStart(11, '0') + '\0', 124);
    block.write('00000000000\0', 136);
    block.write(type, 156);
    block.write('ustar\0', 257);
    block.write('00', 263);
    block.fill(' ', 148, 156);
    const checksum = block.reduce((sum, byte) => sum + byte, 0);
    block.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    return block;
}

const pad = (data: Buffer) =>
    Buffer.concat([data, Buffer.alloc((512 - (data.length % 512)) % 512)]);

/** Build a gzipped npm-style tarball. Names over 100 chars use a PAX header. */
export function tarball(files: Record<string, string | Buffer>, root = 'package'): Buffer {
    const parts: Buffer[] = [];
    for (const [file, content] of Object.entries(files)) {
        const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
        const name = `${root}/${file}`;
        if (name.length > 100) {
            const record = ` path=${name}\n`;
            let length = record.length;
            length += String(length + String(length).length).length;
            const pax = Buffer.from(`${length}${record}`);
            parts.push(header('PaxHeader', pax.length, 'x'), pad(pax));
        }
        parts.push(header(name, data.length), pad(data));
    }
    parts.push(Buffer.alloc(1024));
    return gzipSync(Buffer.concat(parts));
}

export const integrity = (data: Buffer) =>
    `sha512-${createHash('sha512').update(data).digest('base64')}`;

export interface FixtureVersion {
    files?: Record<string, string>;
    publishedAt?: string;
    publisher?: string;
    provenance?: boolean;
    scripts?: Record<string, string>;
    deprecated?: string;
}

/** A RegistryClient backed by in-memory packages. */
export function fakeRegistry(
    packages: Record<string, Record<string, FixtureVersion>>,
    downloads: Record<string, number> = {},
    created?: Record<string, string>
): RegistryClient & { tarballs: Map<string, Buffer> } {
    const tarballs = new Map<string, Buffer>();
    const packuments = new Map<string, Packument>();
    for (const [name, versions] of Object.entries(packages)) {
        const doc: Packument = {
            name,
            'dist-tags': { latest: Object.keys(versions).at(-1)! },
            versions: {},
            time: { created: created?.[name] ?? '2020-01-01T00:00:00.000Z' },
        };
        for (const [version, fixture] of Object.entries(versions)) {
            const manifest = { name, version, scripts: fixture.scripts };
            const data = tarball({
                'package.json': JSON.stringify(manifest),
                ...(fixture.files ?? { 'index.js': 'module.exports = 1;\n' }),
            });
            const url = `https://registry.npmjs.org/${name}/-/${name.replace(/^@[^/]+\//, '')}-${version}.tgz`;
            tarballs.set(url, data);
            const meta: PackumentVersion = {
                name,
                version,
                scripts: fixture.scripts,
                deprecated: fixture.deprecated,
                _npmUser: { name: fixture.publisher ?? 'maintainer' },
                dist: {
                    tarball: url,
                    integrity: integrity(data),
                    ...(fixture.provenance
                        ? { attestations: { url: 'https://example.test/att' } }
                        : {}),
                },
            };
            doc.versions[version] = meta;
            doc.time[version] = fixture.publishedAt ?? '2024-01-01T00:00:00.000Z';
        }
        packuments.set(name, doc);
    }
    return {
        tarballs,
        async packument(name) {
            const doc = packuments.get(name);
            if (!doc) throw new PackageNotFoundError(name);
            return doc;
        },
        async weeklyDownloads(name) {
            return downloads[name];
        },
        async tarball(version) {
            const data = tarballs.get(version.dist.tarball);
            if (!data) throw new Error('missing tarball');
            if (integrity(data) !== version.dist.integrity)
                throw new Error('failed integrity verification');
            return readPackageTarball(data);
        },
    };
}

/** Build a v3 lockfile; integrity comes from the fake registry when it has the tarball. */
export function lockfile(
    packages: Record<
        string,
        { version: string; integrity?: string; resolved?: string; name?: string }
    >,
    registry?: { tarballs: Map<string, Buffer> }
): { name: string; lockfileVersion: number; packages: Record<string, any> } {
    const entries: Record<string, any> = { '': { name: 'app', version: '1.0.0' } };
    for (const [location, value] of Object.entries(packages)) {
        const name = value.name ?? location.slice(location.lastIndexOf('node_modules/') + 13);
        const resolved = `https://registry.npmjs.org/${name}/-/${name.replace(/^@[^/]+\//, '')}-${value.version}.tgz`;
        const data = registry?.tarballs.get(resolved);
        entries[location] = {
            resolved,
            integrity: data ? integrity(data) : `sha512-${name}-${value.version}`,
            ...value,
        };
    }
    return { name: 'app', lockfileVersion: 3, packages: entries };
}

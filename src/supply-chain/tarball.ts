import { createHash } from 'crypto';
import { gunzipSync } from 'zlib';

export const MAX_UNPACKED_BYTES = 64 * 1024 * 1024;
export const MAX_ENTRIES = 20000;

export type PackageFiles = Map<string, Buffer>;

/** Check a buffer against an npm Subresource Integrity string (sha512/sha384/sha256/sha1). */
export function matchesIntegrity(data: Buffer, integrity: string): boolean {
    return integrity
        .trim()
        .split(/\s+/)
        .some((entry) => {
            const match = entry.match(/^(sha512|sha384|sha256|sha1)-(.+)$/);
            return Boolean(
                match && createHash(match[1]).update(data).digest('base64') === match[2]
            );
        });
}

const field = (block: Buffer, start: number, length: number) =>
    block
        .subarray(start, start + length)
        .toString('utf8')
        .replace(/\0.*$/s, '');

function paxPath(data: Buffer): string | undefined {
    let offset = 0;
    const text = data.toString('utf8');
    while (offset < text.length) {
        const space = text.indexOf(' ', offset);
        if (space < 0) break;
        const length = Number(text.slice(offset, space));
        if (!Number.isInteger(length) || length <= 0) break;
        const record = text.slice(space + 1, offset + length - 1);
        if (record.startsWith('path=')) return record.slice(5);
        offset += length;
    }
    return undefined;
}

/**
 * Read a gzipped npm package tarball entirely in memory. Nothing is written to disk, so
 * hostile entry names cannot escape a directory. The leading package directory is removed.
 */
export function readPackageTarball(gzipped: Buffer): PackageFiles {
    const tar = gunzipSync(gzipped, { maxOutputLength: MAX_UNPACKED_BYTES });
    const files: PackageFiles = new Map();
    let offset = 0;
    let longName: string | undefined;
    let entries = 0;
    while (offset + 512 <= tar.length) {
        const header = tar.subarray(offset, offset + 512);
        if (header.every((byte) => byte === 0)) break;
        if (++entries > MAX_ENTRIES) throw new Error('Package tarball has too many entries.');
        const size = parseInt(field(header, 124, 12).trim() || '0', 8);
        if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > tar.length) {
            throw new Error('Malformed package tarball.');
        }
        const type = field(header, 156, 1) || '0';
        const data = tar.subarray(offset + 512, offset + 512 + size);
        offset += 512 + Math.ceil(size / 512) * 512;
        if (type === 'x' || type === 'L') {
            longName = type === 'L' ? data.toString('utf8').replace(/\0.*$/s, '') : paxPath(data);
            continue;
        }
        const prefix = field(header, 345, 155);
        const name =
            longName ?? (prefix ? `${prefix}/${field(header, 0, 100)}` : field(header, 0, 100));
        longName = undefined;
        if (type !== '0') continue;
        const parts = name.replace(/\\/g, '/').split('/').slice(1).filter(Boolean);
        // Entry names are only map keys, but keep them clean for every consumer.
        if (!parts.length || parts.some((part) => part === '..' || part === '.')) continue;
        files.set(parts.join('/'), Buffer.from(data));
    }
    return files;
}

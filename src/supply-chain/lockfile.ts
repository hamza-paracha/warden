import * as semver from 'semver';
import { Signal } from './signals';

export interface LockEntry {
    name: string;
    version: string;
    path: string;
    integrity?: string;
    resolved?: string;
    dev?: boolean;
    bundled?: boolean;
}

export interface LockfileChange {
    added: LockEntry[];
    updated: Array<{ from: LockEntry; to: LockEntry }>;
    removed: LockEntry[];
    signals: Array<Signal & { package: string }>;
}

/** Flatten an npm v2/v3 lockfile into installed package entries. */
export function lockEntries(lock: any): LockEntry[] {
    if (
        ![2, 3].includes(lock?.lockfileVersion) ||
        !lock.packages ||
        typeof lock.packages !== 'object'
    )
        throw new Error('Only npm v2/v3 package-lock.json files are supported.');
    const entries: LockEntry[] = [];
    for (const [location, value] of Object.entries<any>(lock.packages)) {
        if (!location || !value || value.link || typeof value.version !== 'string') continue;
        const marker = location.lastIndexOf('node_modules/');
        if (marker < 0) continue;
        entries.push({
            name: typeof value.name === 'string' ? value.name : location.slice(marker + 13),
            version: value.version,
            path: location,
            integrity: value.integrity,
            resolved: value.resolved,
            dev: Boolean(value.dev),
            bundled: Boolean(value.inBundle),
        });
    }
    return entries;
}

const key = (entry: LockEntry) => `${entry.name}@${entry.version}`;

export function diffLockfiles(
    baseLock: any,
    headLock: any,
    registry = 'https://registry.npmjs.org'
): LockfileChange {
    const origin = new URL(registry).origin;
    const base = lockEntries(baseLock);
    const head = lockEntries(headLock);
    const baseByKey = new Map(base.map((entry) => [key(entry), entry]));
    const headKeys = new Set(head.map(key));
    const baseVersions = new Map<string, LockEntry[]>();
    for (const entry of base)
        baseVersions.set(entry.name, [...(baseVersions.get(entry.name) ?? []), entry]);
    const change: LockfileChange = { added: [], updated: [], removed: [], signals: [] };
    const seen = new Set<string>();
    for (const entry of head) {
        const id = key(entry);
        const previous = baseByKey.get(id);
        if (
            previous?.integrity &&
            entry.integrity &&
            previous.integrity !== entry.integrity &&
            !seen.has(`integrity:${id}`)
        ) {
            seen.add(`integrity:${id}`);
            change.signals.push({
                id: 'integrity-changed',
                severity: 'critical',
                package: id,
                message: 'The lockfile changed the integrity hash of an already-locked version',
                evidence: `${previous.integrity.slice(0, 24)}… → ${entry.integrity.slice(0, 24)}…`,
            });
        }
        const changed = !previous || previous.resolved !== entry.resolved;
        if (changed && !entry.bundled && entry.resolved && !seen.has(`source:${id}`)) {
            let resolvedOrigin: string | undefined;
            try {
                resolvedOrigin = new URL(entry.resolved).origin;
            } catch {
                resolvedOrigin = undefined;
            }
            if (resolvedOrigin !== origin) {
                seen.add(`source:${id}`);
                change.signals.push({
                    id: 'off-registry-source',
                    severity: 'high',
                    package: id,
                    message: 'Resolves from outside the configured registry',
                    evidence: entry.resolved.slice(0, 160),
                });
            }
        }
        if (
            changed &&
            !entry.bundled &&
            entry.resolved &&
            !entry.integrity &&
            !seen.has(`nohash:${id}`)
        ) {
            seen.add(`nohash:${id}`);
            change.signals.push({
                id: 'missing-integrity',
                severity: 'medium',
                package: id,
                message: 'Locked without an integrity hash',
            });
        }
        if (previous || seen.has(id) || entry.bundled) continue;
        seen.add(id);
        const earlier = (baseVersions.get(entry.name) ?? []).filter((e) => semver.valid(e.version));
        if (earlier.length) {
            const from = earlier.sort((a, b) => semver.rcompare(a.version, b.version))[0];
            change.updated.push({ from, to: entry });
        } else change.added.push(entry);
    }
    const removed = new Set<string>();
    const headNames = new Set(head.map((entry) => entry.name));
    for (const entry of base) {
        if (!headKeys.has(key(entry)) && !headNames.has(entry.name) && !removed.has(key(entry))) {
            removed.add(key(entry));
            change.removed.push(entry);
        }
    }
    return change;
}

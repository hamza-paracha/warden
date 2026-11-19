import * as semver from 'semver';
import { matchesIntegrity, PackageFiles, readPackageTarball } from './tarball';

export const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
const MAX_TARBALL_BYTES = 32 * 1024 * 1024;
const MAX_PACKUMENT_BYTES = 64 * 1024 * 1024;

export interface PackumentVersion {
    name: string;
    version: string;
    deprecated?: string;
    scripts?: Record<string, string>;
    repository?: unknown;
    _npmUser?: { name?: string; email?: string; trustedPublisher?: unknown };
    dist: {
        tarball: string;
        integrity?: string;
        shasum?: string;
        attestations?: { url?: string; provenance?: { predicateType?: string } };
    };
}

export interface Packument {
    name: string;
    'dist-tags': Record<string, string>;
    versions: Record<string, PackumentVersion>;
    time: Record<string, string>;
    maintainers?: Array<{ name?: string }>;
}

export class PackageNotFoundError extends Error {
    constructor(public readonly packageName: string) {
        super(`Package ${packageName} does not exist in the registry.`);
        this.name = 'PackageNotFoundError';
    }
}

export interface RegistryClient {
    packument(name: string): Promise<Packument>;
    weeklyDownloads(name: string): Promise<number | undefined>;
    tarball(version: PackumentVersion): Promise<PackageFiles>;
}

export function validPackageName(name: string): boolean {
    return (
        name.length > 0 &&
        name.length <= 214 &&
        /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i.test(name)
    );
}

async function readLimited(response: Response, limit: number): Promise<Buffer> {
    const declared = Number(response.headers.get('content-length'));
    if (declared > limit) throw new Error(`Registry response exceeds ${limit} bytes.`);
    const data = Buffer.from(await response.arrayBuffer());
    if (data.length > limit) throw new Error(`Registry response exceeds ${limit} bytes.`);
    return data;
}

export function createRegistryClient(
    registry = DEFAULT_REGISTRY,
    timeoutMs = 30000,
    fetcher: typeof fetch = fetch
): RegistryClient {
    const base = registry.replace(/\/+$/, '');
    const origin = new URL(base).origin;
    const packuments = new Map<string, Promise<Packument>>();
    const get = (url: string, accept = 'application/json') =>
        fetcher(url, {
            headers: { accept, 'user-agent': 'warden-supply-chain' },
            signal: AbortSignal.timeout(timeoutMs),
            redirect: 'follow',
        });
    return {
        packument(name) {
            if (!validPackageName(name))
                return Promise.reject(new Error(`Invalid package name: ${name}`));
            if (!packuments.has(name)) {
                const request = (async () => {
                    const response = await get(`${base}/${name.replace('/', '%2f')}`);
                    if (response.status === 404) throw new PackageNotFoundError(name);
                    if (!response.ok)
                        throw new Error(`Registry returned ${response.status} for ${name}.`);
                    const document = JSON.parse(
                        (await readLimited(response, MAX_PACKUMENT_BYTES)).toString('utf8')
                    );
                    if (!document?.versions || typeof document.versions !== 'object')
                        throw new Error(`Registry metadata for ${name} has no versions.`);
                    return document as Packument;
                })();
                request.catch(() => packuments.delete(name));
                packuments.set(name, request);
            }
            return packuments.get(name)!;
        },
        async weeklyDownloads(name) {
            if (base !== DEFAULT_REGISTRY) return undefined;
            try {
                const response = await get(
                    `https://api.npmjs.org/downloads/point/last-week/${name}`
                );
                if (!response.ok) return undefined;
                const body = (await response.json()) as { downloads?: number };
                return typeof body.downloads === 'number' ? body.downloads : undefined;
            } catch {
                return undefined;
            }
        },
        async tarball(version) {
            const url = new URL(version.dist.tarball);
            // Only fetch package contents from the configured registry, never an arbitrary host.
            if (url.origin !== origin || url.protocol !== 'https:')
                throw new Error(`Refusing tarball outside ${origin}: ${url.origin}`);
            if (!version.dist.integrity)
                throw new Error(`${version.name}@${version.version} has no integrity hash.`);
            const response = await get(url.toString(), 'application/octet-stream');
            if (!response.ok)
                throw new Error(`Registry returned ${response.status} for ${url.pathname}.`);
            const data = await readLimited(response, MAX_TARBALL_BYTES);
            if (!matchesIntegrity(data, version.dist.integrity))
                throw new Error(
                    `${version.name}@${version.version} failed integrity verification.`
                );
            return readPackageTarball(data);
        },
    };
}

/** Resolve an exact version, dist-tag, or range the way an install would choose it. */
export function resolveVersion(packument: Packument, spec = 'latest'): string | undefined {
    const wanted = spec.trim() || 'latest';
    if (packument.versions[wanted]) return wanted;
    const tagged = packument['dist-tags']?.[wanted];
    if (tagged && packument.versions[tagged]) return tagged;
    const range = semver.validRange(wanted, { loose: true });
    if (!range) return undefined;
    const latest = packument['dist-tags']?.latest;
    if (latest && packument.versions[latest] && semver.satisfies(latest, range)) return latest;
    return semver.maxSatisfying(Object.keys(packument.versions), range) ?? undefined;
}

/** The newest release published before `version`, used as the behavioral baseline. */
export function previousVersion(packument: Packument, version: string): string | undefined {
    const published = packument.time?.[version];
    const candidates = Object.keys(packument.versions).filter(
        (v) =>
            v !== version &&
            semver.valid(v) &&
            !semver.prerelease(v) &&
            (!published || !packument.time?.[v] || packument.time[v] <= published) &&
            semver.lt(v, version)
    );
    return candidates.sort(semver.rcompare)[0];
}

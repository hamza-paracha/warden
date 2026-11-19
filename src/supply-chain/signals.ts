import { createHash } from 'crypto';
import { PackageFiles } from './tarball';

export type RiskSeverity = 'low' | 'medium' | 'high' | 'critical';
export const RISK_RANK: Record<RiskSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export interface Signal {
    id: string;
    severity: RiskSeverity;
    message: string;
    file?: string;
    evidence?: string;
}

export interface CodeDiff {
    filesAdded: string[];
    filesRemoved: string[];
    filesChanged: string[];
    unpackedBytesBefore: number;
    unpackedBytesAfter: number;
    signals: Signal[];
}

interface Pattern {
    id: string;
    severity: RiskSeverity;
    message: string;
    test: (source: string) => RegExpMatchArray | null;
}

const regex =
    (expression: RegExp) =>
    (source: string): RegExpMatchArray | null =>
        source.match(expression);

const CODE_PATTERNS: Pattern[] = [
    {
        id: 'download-and-execute',
        severity: 'critical',
        message: 'Downloads remote content and pipes it into a shell',
        test: regex(/\b(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:ba|z)?sh\b|powershell[^\n]{0,80}-enc/i),
    },
    {
        id: 'secret-scanner',
        severity: 'critical',
        message: 'Bundles or invokes a secret-harvesting tool',
        test: regex(/\b(?:trufflehog|gitleaks)\b/i),
    },
    {
        id: 'credential-access',
        severity: 'high',
        message: 'Reads developer credentials or registry tokens',
        test: regex(
            /\.npmrc\b|\.ssh\/(?:id_|known_hosts)|\.aws\/credentials|\.git-credentials|\.docker\/config\.json|\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY)\b/
        ),
    },
    {
        id: 'env-harvest',
        severity: 'high',
        message: 'Serializes or enumerates the whole process environment',
        test: regex(
            /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env\b/
        ),
    },
    {
        id: 'global-hook',
        severity: 'high',
        message: 'Overrides global network or wallet APIs',
        test: regex(
            /(?:window|globalThis|self)\.fetch\s*=(?!=)|XMLHttpRequest\.prototype\.(?:open|send)\s*=(?!=)|window\.ethereum\b|eth_sendTransaction/
        ),
    },
    {
        id: 'process-spawn',
        severity: 'medium',
        message: 'Spawns child processes',
        test: regex(
            /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s*['"](?:node:)?child_process['"]|import\(\s*['"](?:node:)?child_process['"]\s*\)/
        ),
    },
    {
        id: 'network',
        severity: 'medium',
        message: 'Opens network connections',
        test: regex(
            /require\(\s*['"](?:node:)?(?:https?|net|tls|dgram|dns)['"]\s*\)|from\s*['"](?:node:)?(?:https?|net|tls|dgram|dns)['"]|\bfetch\s*\(\s*['"`]https?:|new\s+WebSocket\s*\(/
        ),
    },
    {
        id: 'dynamic-code',
        severity: 'medium',
        message: 'Evaluates dynamically constructed code',
        test: regex(/\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn(?:New|This)?Context\s*\(/),
    },
];

const CODE_FILE = /\.(?:[cm]?js|jsx|[cm]?ts|tsx|sh|bash|ps1|py|json)$/i;
const BINARY_FILE = /\.(?:node|exe|dll|so|dylib|wasm|bin)$/i;
const MAX_ANALYZED_BYTES = 4 * 1024 * 1024;
const TYPE_DECLARATION = /\.d\.[cm]?ts$/i;
const INERT_PATH =
    /(?:^|\/)(?:tests?|__tests__|spec|examples?|docs?|benchmarks?)\/|(?:^|\/)[^/]*\.(?:test|spec)\.[cm]?[jt]sx?$|^test\.[cm]?js$/i;
const LOWER: Record<RiskSeverity, RiskSeverity> = {
    critical: 'high',
    high: 'medium',
    medium: 'low',
    low: 'low',
};

function isBinary(data: Buffer): boolean {
    return data.subarray(0, 8192).includes(0);
}

/** Obfuscators emit long hex identifiers, dense escapes, or huge single lines. */
export function obfuscationEvidence(source: string): string | undefined {
    const hexIdentifiers = source.match(/\b_0x[0-9a-f]{4,6}\b/g)?.length ?? 0;
    if (hexIdentifiers >= 20) return `${hexIdentifiers} _0x-style identifiers`;
    const escapes = source.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi)?.length ?? 0;
    if (source.length > 2000 && escapes * 4 > source.length * 0.25)
        return `${escapes} hex/unicode escapes`;
    return undefined;
}

const longestLine = (source: string) =>
    source.split('\n').reduce((max, line) => Math.max(max, line.length), 0);

function snippet(source: string, match: RegExpMatchArray): string {
    const index = match.index ?? 0;
    return source
        .slice(Math.max(0, index - 40), index + match[0].length + 40)
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 160);
}

export function fileSignals(file: string, data: Buffer): Signal[] {
    if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(file)) {
        return [
            {
                id: 'ci-workflow',
                severity: 'high',
                message: 'Ships a GitHub Actions workflow inside the package',
                file,
            },
        ];
    }
    if (BINARY_FILE.test(file) || (!CODE_FILE.test(file) && isBinary(data))) {
        return [
            {
                id: 'binary',
                severity: 'medium',
                message: 'Contains a native or opaque binary',
                file,
            },
        ];
    }
    if (
        !CODE_FILE.test(file) ||
        TYPE_DECLARATION.test(file) ||
        isBinary(data) ||
        data.length > MAX_ANALYZED_BYTES
    )
        return [];
    const source = data.toString('utf8');
    const signals: Signal[] = [];
    for (const pattern of CODE_PATTERNS) {
        const match = pattern.test(source);
        if (match)
            signals.push({
                id: pattern.id,
                severity: pattern.severity,
                message: pattern.message,
                file,
                evidence: snippet(source, match),
            });
    }
    const obfuscated = /\.(?:[cm]?js|jsx)$/i.test(file) ? obfuscationEvidence(source) : undefined;
    if (obfuscated)
        signals.push({
            id: 'obfuscation',
            severity: 'high',
            message: 'Contains obfuscated code',
            file,
            evidence: obfuscated,
        });
    // Tests and examples ship in many packages but are not loaded by consumers.
    return INERT_PATH.test(file)
        ? signals.map((signal) => ({ ...signal, severity: LOWER[signal.severity] }))
        : signals;
}

// `prepare` only runs for git/local installs, never for registry tarballs.
const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall'];

export function installScripts(manifest: any): Record<string, string> {
    const scripts: Record<string, string> = {};
    for (const name of LIFECYCLE_SCRIPTS) {
        const value = manifest?.scripts?.[name];
        if (typeof value === 'string' && value.trim()) scripts[name] = value;
    }
    return scripts;
}

/** Compare install scripts; a newly added or rewritten lifecycle script is a strong signal. */
export function scriptSignals(before: any | undefined, after: any): Signal[] {
    const previous = before ? installScripts(before) : {};
    const current = installScripts(after);
    const signals: Signal[] = [];
    for (const [name, command] of Object.entries(current)) {
        if (previous[name] === command) continue;
        const added = !(name in previous);
        signals.push({
            id: added ? 'install-script-added' : 'install-script-changed',
            severity: before ? 'high' : 'medium',
            message: `${added ? 'Adds' : 'Changes'} the ${name} lifecycle script`,
            file: 'package.json',
            evidence: command.slice(0, 160),
        });
        for (const pattern of CODE_PATTERNS) {
            const match = pattern.test(command);
            if (match && RISK_RANK[pattern.severity] >= RISK_RANK.high)
                signals.push({
                    id: pattern.id,
                    severity: pattern.severity,
                    message: `${pattern.message} (in ${name} script)`,
                    file: 'package.json',
                    evidence: command.slice(0, 160),
                });
        }
    }
    return signals;
}

const digest = (data: Buffer) => createHash('sha256').update(data).digest('hex');
const sum = (files: PackageFiles) => [...files.values()].reduce((n, d) => n + d.length, 0);

export function parseManifest(files: PackageFiles | undefined): any | undefined {
    const raw = files?.get('package.json');
    if (!raw) return undefined;
    try {
        return JSON.parse(raw.toString('utf8'));
    } catch {
        return undefined;
    }
}

/**
 * Report behavior a release adds relative to the previous one. Signals already present in the
 * same file of the previous release are not repeated, so established packages stay quiet.
 */
export function diffPackages(before: PackageFiles | undefined, after: PackageFiles): CodeDiff {
    const previous = before ?? new Map<string, Buffer>();
    const filesAdded: string[] = [];
    const filesChanged: string[] = [];
    const signals: Signal[] = [];
    for (const [file, data] of after) {
        const old = previous.get(file);
        if (old && digest(old) === digest(data)) continue;
        (old ? filesChanged : filesAdded).push(file);
        if (file === 'package.json') continue;
        const known = new Set(old ? fileSignals(file, old).map((s) => s.id) : []);
        for (const signal of fileSignals(file, data)) {
            if (!known.has(signal.id)) signals.push(signal);
        }
        if (/\.(?:[cm]?js)$/i.test(file) && old && !/\.min\.[cm]?js$/i.test(file)) {
            const source = data.toString('utf8');
            if (longestLine(source) > 20000 && longestLine(old.toString('utf8')) < 2000)
                signals.push({
                    id: 'minified-rewrite',
                    severity: 'medium',
                    message: 'A readable source file was replaced by a minified blob',
                    file,
                });
        }
    }
    return {
        filesAdded: filesAdded.sort(),
        filesRemoved: [...previous.keys()].filter((file) => !after.has(file)).sort(),
        filesChanged: filesChanged.sort(),
        unpackedBytesBefore: sum(previous),
        unpackedBytesAfter: sum(after),
        signals,
    };
}

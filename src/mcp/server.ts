import * as path from 'path';
import * as readline from 'readline';
import { checkInstallCommand, formatCommandCheck } from '../guard';
import {
    assessPackage,
    formatAssessment,
    formatReviewMarkdown,
    loadSupplyChainPolicy,
    parsePackageSpec,
    reviewDependencyChange,
} from '../supply-chain';

const SUPPORTED_PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

interface Tool {
    name: string;
    title: string;
    description: string;
    inputSchema: Record<string, unknown>;
    run: (args: any) => Promise<{ text: string; data: unknown; isError?: boolean }>;
}

const str = (description: string) => ({ type: 'string', description });

export const TOOLS: Tool[] = [
    {
        name: 'check_packages',
        title: 'Check npm packages before installing',
        description:
            'Call before adding any npm dependency. Detects nonexistent (hallucinated) names, typosquats, ' +
            'releases younger than policy, dropped provenance, new publishers, new install scripts, and ' +
            'risky code a release adds compared with its predecessor. Returns allow, warn, or block per package.',
        inputSchema: {
            type: 'object',
            properties: {
                packages: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Package specs such as "chalk", "lodash@^4", "@scope/pkg@1.2.3"',
                    minItems: 1,
                    maxItems: 50,
                },
                cwd: str('Project directory whose .wardenrc.json policy applies'),
            },
            required: ['packages'],
        },
        async run(args) {
            if (
                !Array.isArray(args?.packages) ||
                !args.packages.length ||
                args.packages.length > 50
            )
                throw new Error('packages must be a non-empty array of at most 50 specs.');
            const policy = loadSupplyChainPolicy(args.cwd ? path.resolve(args.cwd) : process.cwd());
            const results = await Promise.all(
                args.packages.map((spec: unknown) => {
                    if (typeof spec !== 'string') throw new Error('Each package must be a string.');
                    const { name, range } = parsePackageSpec(spec.trim());
                    return assessPackage(name, range, { policy });
                })
            );
            return { text: results.map(formatAssessment).join('\n\n'), data: { results } };
        },
    },
    {
        name: 'check_install_command',
        title: 'Check a shell install command',
        description:
            'Parse an npm/npx/pnpm/yarn/bun shell command and check every package it would install or execute.',
        inputSchema: {
            type: 'object',
            properties: {
                command: str('The shell command to check'),
                cwd: str('Working directory'),
            },
            required: ['command'],
        },
        async run(args) {
            if (typeof args?.command !== 'string') throw new Error('command must be a string.');
            const check = await checkInstallCommand(args.command, {
                cwd: args.cwd ? path.resolve(args.cwd) : undefined,
            });
            return {
                text: check.targets.length
                    ? `Verdict: ${check.verdict.toUpperCase()}\n${formatCommandCheck(check)}`
                    : 'The command installs no registry packages.',
                data: check,
            };
        },
    },
    {
        name: 'review_dependency_change',
        title: 'Review a lockfile change between two commits',
        description:
            'Compare package-lock.json between two Git revisions and assess every newly installed release ' +
            'for supply-chain risk. Use before opening or approving a dependency pull request.',
        inputSchema: {
            type: 'object',
            properties: {
                repository: str('Path to a local Git repository'),
                base: str('Base revision, e.g. main'),
                head: str('Candidate revision, e.g. HEAD'),
                lockfile: str('Repository-relative lockfile path (default package-lock.json)'),
            },
            required: ['repository', 'base', 'head'],
        },
        async run(args) {
            for (const key of ['repository', 'base', 'head'])
                if (typeof args?.[key] !== 'string' || !args[key])
                    throw new Error(`${key} is required.`);
            const review = await reviewDependencyChange({
                repository: path.resolve(args.repository),
                base: args.base,
                head: args.head,
                lockfile: args.lockfile,
            });
            return {
                text: formatReviewMarkdown(review),
                data: review,
                isError: review.status !== 'passed',
            };
        },
    },
    {
        name: 'verify_dependency_fix',
        title: 'Verify a dependency security fix',
        description:
            'Rescan base and candidate commits with npm audit, confirm the target advisories are resolved, ' +
            'run the tests (Docker by default), review newly installed releases, and write an evidence bundle.',
        inputSchema: {
            type: 'object',
            properties: {
                repository: str('Path to a local Git repository'),
                base: str('Base revision'),
                head: str('Candidate revision'),
                advisories: {
                    type: 'array',
                    items: { type: 'string' },
                    minItems: 1,
                    description: 'GHSA IDs',
                },
                testCommand: {
                    type: 'array',
                    items: { type: 'string' },
                    minItems: 1,
                    description: 'Test argument vector, e.g. ["npm","test"]',
                },
                runner: {
                    type: 'string',
                    enum: ['docker', 'trusted-host'],
                    description: 'Default docker',
                },
                severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
            },
            required: ['repository', 'base', 'head', 'advisories', 'testCommand'],
        },
        async run(args) {
            const { verifyChange } = await import('../verification');
            const repository = path.resolve(String(args?.repository ?? ''));
            const evidence = await verifyChange({
                repository,
                base: args.base,
                head: args.head,
                advisories: args.advisories,
                testCommand: args.testCommand,
                runner: args.runner ?? 'docker',
                severity: args.severity ?? 'high',
                timeoutMs: 120000,
                output: path.join(repository, 'scan-results', 'verification'),
            });
            return {
                text: `Verification ${evidence.status}: ${evidence.reasons.join(' ') || 'all configured checks passed.'}`,
                data: evidence,
                isError: evidence.status !== 'passed',
            };
        },
    },
];

type Message = { jsonrpc?: string; id?: string | number | null; method?: string; params?: any };

export async function handleMessage(
    message: Message,
    version: string
): Promise<object | undefined> {
    const reply = (result: unknown) => ({ jsonrpc: '2.0', id: message.id, result });
    const fail = (code: number, text: string) => ({
        jsonrpc: '2.0',
        id: message.id ?? null,
        error: { code, message: text },
    });
    if (!message || typeof message !== 'object' || typeof message.method !== 'string')
        return message?.id !== undefined ? fail(-32600, 'Invalid request') : undefined;
    const isNotification = message.id === undefined || message.id === null;
    switch (message.method) {
        case 'initialize': {
            const requested = message.params?.protocolVersion;
            return reply({
                protocolVersion: SUPPORTED_PROTOCOLS.includes(requested)
                    ? requested
                    : SUPPORTED_PROTOCOLS[0],
                capabilities: { tools: { listChanged: false } },
                serverInfo: { name: 'warden', title: 'Warden supply-chain guard', version },
                instructions:
                    'Before installing or upgrading any npm package, call check_packages (or check_install_command). ' +
                    'Do not install packages whose verdict is block; explain the signals to the user instead.',
            });
        }
        case 'ping':
            return reply({});
        case 'tools/list':
            return reply({
                tools: TOOLS.map(({ name, title, description, inputSchema }) => ({
                    name,
                    title,
                    description,
                    inputSchema,
                })),
            });
        case 'tools/call': {
            const tool = TOOLS.find((t) => t.name === message.params?.name);
            if (!tool) return fail(-32602, `Unknown tool: ${message.params?.name}`);
            try {
                const { text, data, isError } = await tool.run(message.params?.arguments ?? {});
                return reply({
                    content: [{ type: 'text', text }],
                    structuredContent: data,
                    isError: Boolean(isError),
                });
            } catch (error) {
                return reply({
                    content: [
                        {
                            type: 'text',
                            text: error instanceof Error ? error.message : String(error),
                        },
                    ],
                    isError: true,
                });
            }
        }
        default:
            return isNotification ? undefined : fail(-32601, `Method not found: ${message.method}`);
    }
}

/** Serve MCP over newline-delimited JSON-RPC on stdio. Logs go to stderr only. */
export function startMcpServer(
    version: string,
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stdout
): Promise<void> {
    // Anything printed to stdout would corrupt the protocol stream.
    console.log = console.info = (...args: unknown[]) => console.error(...args);
    const lines = readline.createInterface({ input, crlfDelay: Infinity });
    const pending = new Set<Promise<void>>();
    const send = (value: object | undefined) => {
        if (value) output.write(`${JSON.stringify(value)}\n`);
    };
    lines.on('line', (line) => {
        if (!line.trim()) return;
        let parsed: Message | Message[];
        try {
            parsed = JSON.parse(line);
        } catch {
            send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
            return;
        }
        const task = (async () => {
            if (Array.isArray(parsed)) {
                const responses = (
                    await Promise.all(parsed.map((m) => handleMessage(m, version)))
                ).filter(Boolean);
                if (responses.length) send(responses as object);
            } else send(await handleMessage(parsed, version));
        })();
        pending.add(task);
        task.finally(() => pending.delete(task));
    });
    return new Promise((resolve) =>
        lines.on('close', () => Promise.all(pending).then(() => resolve()))
    );
}

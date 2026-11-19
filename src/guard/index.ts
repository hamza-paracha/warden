import * as fs from 'fs';
import * as path from 'path';
import {
    assessPackage,
    formatAssessment,
    loadSupplyChainPolicy,
    PackageAssessment,
    RegistryClient,
    SupplyChainPolicy,
    Verdict,
} from '../supply-chain';
import { findInstallTargets, InstallTarget } from './install-command';

export { findInstallTargets, tokenize } from './install-command';
export type { InstallTarget } from './install-command';

export interface CommandCheck {
    command: string;
    verdict: Verdict;
    targets: InstallTarget[];
    assessments: PackageAssessment[];
    unverifiable: string[];
    errors: string[];
}

export async function checkInstallCommand(
    command: string,
    options: { cwd?: string; policy?: SupplyChainPolicy; client?: RegistryClient } = {}
): Promise<CommandCheck> {
    const cwd = options.cwd ?? process.cwd();
    const policy = options.policy ?? loadSupplyChainPolicy(cwd);
    const targets = findInstallTargets(command, cwd);
    const unique = new Map<string, InstallTarget>();
    for (const target of targets)
        if (target.name) unique.set(`${target.name}@${target.range ?? ''}`, target);
    const assessments = await Promise.all(
        [...unique.values()].map((t) =>
            assessPackage(t.name!, t.range, { policy, client: options.client })
        )
    );
    const unverifiable = targets.filter((t) => t.source).map((t) => t.spec);
    const verdicts = assessments.map((a) => a.verdict);
    const verdict: Verdict = verdicts.includes('block')
        ? 'block'
        : verdicts.includes('warn') || unverifiable.length
          ? 'warn'
          : 'allow';
    return {
        command,
        verdict,
        targets,
        assessments,
        unverifiable,
        errors: assessments.flatMap((a) => a.errors.map((e) => `${a.name}: ${e}`)),
    };
}

export function formatCommandCheck(check: CommandCheck): string {
    return [
        ...check.assessments.map(formatAssessment),
        ...check.unverifiable.map(
            (spec) =>
                `WARN ${spec}\n  - [medium] Installs from outside the registry; Warden cannot inspect its release history`
        ),
    ].join('\n');
}

export interface HookResult {
    exitCode: number;
    stdout: string;
    stderr: string;
}

/**
 * PreToolUse hook for Claude Code and Devin. Reads the hook payload, checks any packages
 * the shell command would install, and blocks with exit code 2 when policy says so.
 * Registry outages fail open unless failClosed is set, so agents keep working offline.
 */
export async function runGuardHook(
    payload: string,
    options: {
        cwd?: string;
        failClosed?: boolean;
        policy?: SupplyChainPolicy;
        client?: RegistryClient;
    } = {}
): Promise<HookResult> {
    let input: any;
    try {
        input = JSON.parse(payload || '{}');
    } catch {
        return {
            exitCode: 0,
            stdout: '',
            stderr: 'warden guard: ignoring unreadable hook payload\n',
        };
    }
    const command = input?.tool_input?.command ?? input?.tool_input?.cmd;
    if (typeof command !== 'string' || !command.trim())
        return { exitCode: 0, stdout: '', stderr: '' };
    const cwd =
        (typeof input.cwd === 'string' && input.cwd) ||
        (typeof input.tool_input?.workdir === 'string' && input.tool_input.workdir) ||
        process.env.DEVIN_PROJECT_DIR ||
        process.env.CLAUDE_PROJECT_DIR ||
        options.cwd ||
        process.cwd();
    const check = await checkInstallCommand(command, { ...options, cwd });
    if (!check.targets.length) return { exitCode: 0, stdout: '', stderr: '' };
    const report = formatCommandCheck(check);
    if (check.verdict === 'block' || (options.failClosed && check.errors.length)) {
        const reason =
            `Warden blocked this install:\n${report}\n` +
            'Choose a different package or version, or ask the user to add it to supplyChain.allow in .wardenrc.json after review.';
        return {
            exitCode: 2,
            stdout: JSON.stringify({ decision: 'block', reason }),
            stderr: `${reason}\n`,
        };
    }
    return { exitCode: 0, stdout: '', stderr: report ? `Warden: ${report}\n` : '' };
}

export type Agent = 'claude' | 'devin' | 'codex';

function readJson(file: string): any {
    if (!fs.existsSync(file)) return {};
    const text = fs.readFileSync(file, 'utf8');
    if (!text.trim()) return {};
    try {
        return JSON.parse(text);
    } catch {
        throw new Error(`${file} is not valid JSON; fix it before installing Warden.`);
    }
}

function writeJson(file: string, value: unknown): void {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function addHook(hooks: any, matcher: string, command: string): boolean {
    hooks.PreToolUse ||= [];
    const present = hooks.PreToolUse.some((group: any) =>
        group?.hooks?.some(
            (hook: any) =>
                typeof hook?.command === 'string' && /warden\b.*\bguard\b/.test(hook.command)
        )
    );
    if (present) return false;
    hooks.PreToolUse.push({
        matcher,
        hooks: [{ type: 'command', command: `${command} guard --hook`, timeout: 60 }],
    });
    return true;
}

export interface SetupResult {
    agent: Agent;
    changed: string[];
    unchanged: string[];
    instructions?: string;
}

/** Register the Warden MCP server and install guard hook in a project's agent config. */
export function setupAgent(
    agent: Agent,
    projectDir: string,
    options: { command?: string; hooks?: boolean; mcp?: boolean } = {}
): SetupResult {
    const command = options.command ?? 'warden';
    const [executable, ...prefix] = command.split(' ').filter(Boolean);
    const server = { command: executable, args: [...prefix, 'mcp'] };
    const result: SetupResult = { agent, changed: [], unchanged: [] };
    const track = (file: string, changed: boolean) =>
        (changed ? result.changed : result.unchanged).push(path.relative(projectDir, file) || file);
    if (agent === 'codex') {
        result.instructions = [
            'Add to ~/.codex/config.toml:',
            '',
            '[mcp_servers.warden]',
            `command = ${JSON.stringify(server.command)}`,
            `args = ${JSON.stringify(server.args)}`,
        ].join('\n');
        return result;
    }
    if (options.mcp !== false) {
        const file = path.join(
            projectDir,
            agent === 'claude' ? '.mcp.json' : '.devin/mcp_config.json'
        );
        const config = readJson(file);
        config.mcpServers ||= {};
        const changed = JSON.stringify(config.mcpServers.warden) !== JSON.stringify(server);
        config.mcpServers.warden = server;
        if (changed) writeJson(file, config);
        track(file, changed);
    }
    if (options.hooks !== false) {
        if (agent === 'claude') {
            const file = path.join(projectDir, '.claude/settings.json');
            const config = readJson(file);
            config.hooks ||= {};
            const changed = addHook(config.hooks, 'Bash', command);
            if (changed) writeJson(file, config);
            track(file, changed);
        } else {
            const file = path.join(projectDir, '.devin/hooks.v1.json');
            const config = readJson(file);
            const changed = addHook(config, 'exec', command);
            if (changed) writeJson(file, config);
            track(file, changed);
        }
    }
    return result;
}

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    checkInstallCommand,
    findInstallTargets,
    formatCommandCheck,
    runGuardHook,
    setupAgent,
    tokenize,
} from '../src/guard';
import { DEFAULT_POLICY } from '../src/supply-chain';
import { fakeRegistry } from './helpers/npm-fixtures';

const specs = (command: string, cwd?: string) =>
    findInstallTargets(command, cwd).map((t) =>
        t.source
            ? `source:${t.spec}`
            : `${t.name}${t.range ? `@${t.range}` : ''}${t.executes ? '!' : ''}`
    );

describe('install command parsing', () => {
    it('tokenizes quotes, escapes, comments, and operators without evaluating', () => {
        expect(tokenize(`a "b c" 'd' e\\ f && g; h | i # comment`)).toEqual([
            ['a', 'b c', 'd', 'e f'],
            ['g'],
            ['h'],
            ['i'],
        ]);
        expect(tokenize('echo "$(rm -rf /)"')).toEqual([['echo', '$(rm -rf /)']]);
    });

    it.each([
        ['npm install chalk', ['chalk']],
        [
            'npm i -D lodash@^4 @types/node@22 --registry https://r.test',
            ['lodash@^4', '@types/node@22'],
        ],
        ['cd app && CI=1 sudo npm add --save-exact left-pad@1.3.0', ['left-pad@1.3.0']],
        ['npm isntall typo', ['typo']],
        ['npm install', []],
        ['npm ci && npm test', []],
        ['npx create-react-app my-app', ['create-react-app!']],
        ['npx -y --package=cowsay@1 cowsay hi', ['cowsay@1!']],
        ['npm exec -- prettier@3 --write .', ['prettier@3!']],
        ['npm create vite@latest app', ['create-vite@latest!']],
        ['npm init @scope', ['@scope/create!']],
        ['pnpm add zod && pnpm dlx tsx script.ts', ['zod', 'tsx!']],
        ['yarn add react react-dom && yarn global add serve', ['react', 'react-dom', 'serve']],
        ['bun add hono && bunx cowsay && bun x figlet', ['hono', 'cowsay!', 'figlet!']],
        ['npm i alias@npm:real-pkg@2', ['real-pkg@2']],
        [
            'npm i user/repo ./local git+https://x.test/r.git https://x.test/a.tgz',
            [
                'source:user/repo',
                'source:./local',
                'source:git+https://x.test/r.git',
                'source:https://x.test/a.tgz',
            ],
        ],
        ['/usr/local/bin/npm.cmd install x', ['x']],
        ['git commit -m "npm install evil"', []],
    ])('%s', (command, expected) => {
        expect(specs(command)).toEqual(expected);
    });

    it('skips npx for binaries installed locally', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-guard-'));
        try {
            fs.mkdirSync(path.join(dir, 'node_modules/.bin'), { recursive: true });
            fs.writeFileSync(path.join(dir, 'node_modules/.bin/jest'), '');
            expect(specs('npx jest --watch', dir)).toEqual([]);
            expect(specs('npx jest@29', dir)).toEqual(['jest@29!']);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('guard', () => {
    const client = fakeRegistry({ good: { '1.0.0': {}, '1.0.1': {} } });
    const policy = { ...DEFAULT_POLICY, minReleaseAgeHours: 0 };

    it('summarizes a command and treats non-registry sources as warnings', async () => {
        const check = await checkInstallCommand('npm i good good user/repo', { policy, client });
        expect(check.assessments).toHaveLength(1);
        expect(check.verdict).toBe('warn');
        expect(formatCommandCheck(check)).toContain('Installs from outside the registry');
        expect((await checkInstallCommand('npm i good', { policy, client })).verdict).toBe('allow');
    });

    it('blocks hallucinated packages with exit code 2 and a structured reason', async () => {
        const payload = JSON.stringify({
            tool_name: 'Bash',
            cwd: os.tmpdir(),
            tool_input: { command: 'npm install good made-up-thing' },
        });
        const result = await runGuardHook(payload, { policy, client });
        expect(result.exitCode).toBe(2);
        expect(JSON.parse(result.stdout)).toMatchObject({ decision: 'block' });
        expect(result.stderr).toContain('made-up-thing does not exist');
    });

    it('allows unrelated commands and unreadable payloads, and can fail closed', async () => {
        expect(
            await runGuardHook(JSON.stringify({ tool_input: { command: 'ls -la' } }), {
                policy,
                client,
            })
        ).toEqual({ exitCode: 0, stdout: '', stderr: '' });
        expect(await runGuardHook('{}', { policy, client })).toMatchObject({ exitCode: 0 });
        expect((await runGuardHook('not json', { policy, client })).exitCode).toBe(0);
        const offline = { ...client, packument: () => Promise.reject(new Error('offline')) };
        const payload = JSON.stringify({ tool_input: { command: 'npm i good' } });
        expect((await runGuardHook(payload, { policy, client: offline })).exitCode).toBe(0);
        expect(
            (await runGuardHook(payload, { policy, client: offline, failClosed: true })).exitCode
        ).toBe(2);
        expect((await runGuardHook(payload, { policy, client })).exitCode).toBe(0);
    });
});

describe('agent setup', () => {
    let dir: string;
    beforeEach(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-setup-'))));
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
    const read = (file: string) => JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));

    it('configures Claude Code while preserving existing settings, idempotently', () => {
        fs.mkdirSync(path.join(dir, '.claude'));
        fs.writeFileSync(
            path.join(dir, '.claude/settings.json'),
            JSON.stringify({ permissions: { allow: ['x'] } })
        );
        const first = setupAgent('claude', dir);
        expect(first.changed.sort()).toEqual(['.claude/settings.json', '.mcp.json']);
        expect(read('.claude/settings.json').permissions.allow).toEqual(['x']);
        expect(read('.claude/settings.json').hooks.PreToolUse[0]).toMatchObject({
            matcher: 'Bash',
        });
        expect(read('.mcp.json').mcpServers.warden).toEqual({ command: 'warden', args: ['mcp'] });
        expect(setupAgent('claude', dir).changed).toEqual([]);
    });

    it('configures Devin, custom commands, and prints Codex instructions', () => {
        const result = setupAgent('devin', dir, { command: 'node /opt/warden/dist/index.js' });
        expect(result.changed.sort()).toEqual(['.devin/hooks.v1.json', '.devin/mcp_config.json']);
        expect(read('.devin/hooks.v1.json').PreToolUse[0]).toMatchObject({
            matcher: 'exec',
            hooks: [{ command: 'node /opt/warden/dist/index.js guard --hook' }],
        });
        expect(read('.devin/mcp_config.json').mcpServers.warden.args).toEqual([
            '/opt/warden/dist/index.js',
            'mcp',
        ]);
        expect(setupAgent('codex', dir).instructions).toContain('[mcp_servers.warden]');
        expect(setupAgent('devin', dir, { hooks: false, mcp: false }).changed).toEqual([]);
        fs.writeFileSync(path.join(dir, '.mcp.json'), '{broken');
        expect(() => setupAgent('claude', dir)).toThrow('not valid JSON');
    });
});

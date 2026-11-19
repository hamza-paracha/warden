import { PassThrough } from 'stream';
import { handleMessage, startMcpServer, TOOLS } from '../src/mcp/server';
import * as supplyChain from '../src/supply-chain';

describe('MCP server', () => {
    afterEach(() => jest.restoreAllMocks());

    it('negotiates the protocol and lists tools with schemas', async () => {
        const init: any = await handleMessage(
            {
                jsonrpc: '2.0',
                id: 1,
                method: 'initialize',
                params: { protocolVersion: '2025-06-18' },
            },
            '9.9.9'
        );
        expect(init.result).toMatchObject({
            protocolVersion: '2025-06-18',
            serverInfo: { name: 'warden', version: '9.9.9' },
        });
        const fallback: any = await handleMessage(
            { id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } },
            '1'
        );
        expect(fallback.result.protocolVersion).toBe('2025-11-25');
        const list: any = await handleMessage({ id: 3, method: 'tools/list' }, '1');
        expect(list.result.tools.map((t: any) => t.name)).toEqual(TOOLS.map((t) => t.name));
        expect(list.result.tools.every((t: any) => t.inputSchema.type === 'object')).toBe(true);
        expect(((await handleMessage({ id: 4, method: 'ping' }, '1')) as any).result).toEqual({});
    });

    it('ignores notifications and reports unknown methods and tools', async () => {
        expect(await handleMessage({ method: 'notifications/initialized' }, '1')).toBeUndefined();
        expect(((await handleMessage({ id: 5, method: 'nope' }, '1')) as any).error.code).toBe(
            -32601
        );
        expect(((await handleMessage({ id: 6 } as any, '1')) as any).error.code).toBe(-32600);
        expect(
            (
                (await handleMessage(
                    { id: 7, method: 'tools/call', params: { name: 'x' } },
                    '1'
                )) as any
            ).error.code
        ).toBe(-32602);
    });

    it('returns tool failures as isError results instead of protocol errors', async () => {
        const response: any = await handleMessage(
            { id: 8, method: 'tools/call', params: { name: 'check_packages', arguments: {} } },
            '1'
        );
        expect(response.result.isError).toBe(true);
        expect(response.result.content[0].text).toContain('packages must be');
        const missing: any = await handleMessage(
            {
                id: 9,
                method: 'tools/call',
                params: { name: 'review_dependency_change', arguments: {} },
            },
            '1'
        );
        expect(missing.result.content[0].text).toContain('repository is required');
    });

    it('runs check_packages and check_install_command', async () => {
        jest.spyOn(supplyChain, 'assessPackage').mockImplementation(async (name, requested) => ({
            name,
            requested,
            verdict: name === 'bad' ? 'block' : 'allow',
            allowlisted: false,
            signals: [],
            errors: [],
        }));
        const result: any = await handleMessage(
            {
                id: 10,
                method: 'tools/call',
                params: { name: 'check_packages', arguments: { packages: ['good@1', 'bad'] } },
            },
            '1'
        );
        expect(result.result.structuredContent.results.map((r: any) => r.verdict)).toEqual([
            'allow',
            'block',
        ]);
        const command: any = await handleMessage(
            {
                id: 11,
                method: 'tools/call',
                params: { name: 'check_install_command', arguments: { command: 'npm i bad' } },
            },
            '1'
        );
        expect(command.result.content[0].text).toContain('Verdict: BLOCK');
        const none: any = await handleMessage(
            {
                id: 12,
                method: 'tools/call',
                params: { name: 'check_install_command', arguments: { command: 'ls' } },
            },
            '1'
        );
        expect(none.result.content[0].text).toContain('installs no registry packages');
    });

    it('serves newline-delimited JSON-RPC over streams, including batches and parse errors', async () => {
        const input = new PassThrough();
        const output = new PassThrough();
        const lines: any[] = [];
        output.on('data', (chunk) =>
            lines.push(
                ...chunk
                    .toString()
                    .trim()
                    .split('\n')
                    .map((l: string) => JSON.parse(l))
            )
        );
        const log = console.log;
        const done = startMcpServer('1', input, output);
        input.write('{"jsonrpc":"2.0","id":1,"method":"ping"}\n');
        input.write('not json\n\n');
        input.end(
            '[{"jsonrpc":"2.0","id":2,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]\n'
        );
        await done;
        console.log = log;
        expect(lines).toEqual(
            expect.arrayContaining([
                { jsonrpc: '2.0', id: 1, result: {} },
                { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
                [{ jsonrpc: '2.0', id: 2, result: {} }],
            ])
        );
    });
});

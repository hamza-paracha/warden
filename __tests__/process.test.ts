import { runProcess, ProcessError } from '../src/services/process';

jest.mock('../src/utils/logger', () => ({ logger: { debug: jest.fn() } }));

describe('argument-vector process execution', () => {
    it('passes shell metacharacters literally', async () => {
        const argument = 'spaces; $(echo unsafe) `echo unsafe` "quoted"';
        const result = await runProcess(process.execPath, [
            '-e',
            'process.stdout.write(process.argv[1])',
            argument,
        ]);
        expect(result.stdout).toBe(argument);
        expect(result.exitCode).toBe(0);
    });
    it('captures findings on an explicitly allowed nonzero exit', async () => {
        const result = await runProcess(
            process.execPath,
            ['-e', 'console.log("findings"); process.exit(1)'],
            { allowedExitCodes: [0, 1] }
        );
        expect(result.stdout.trim()).toBe('findings');
        expect(result.exitCode).toBe(1);
    });
    it('rejects operational failures even if stdout is valid JSON', async () => {
        await expect(
            runProcess(process.execPath, ['-e', 'console.log("{}"); process.exit(2)'], {
                allowedExitCodes: [0, 1],
            })
        ).rejects.toBeInstanceOf(ProcessError);
    });
    it('rejects timeouts with partial output', async () => {
        await expect(
            runProcess(process.execPath, ['-e', 'console.log("{}"); setInterval(() => {}, 1000)'], {
                timeout: 100,
                allowedExitCodes: [0, 1],
            })
        ).rejects.toMatchObject({ killed: true });
    });
    it('rejects output exceeding the buffer limit', async () => {
        await expect(
            runProcess(process.execPath, ['-e', 'console.log("x".repeat(10000))'], {
                maxBuffer: 100,
            })
        ).rejects.toBeInstanceOf(ProcessError);
    });
    it('supports cancellation', async () => {
        const controller = new AbortController();
        controller.abort();
        await expect(
            runProcess(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
                signal: controller.signal,
            })
        ).rejects.toBeInstanceOf(ProcessError);
    });
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runProcess } from '../src/services/process';
import { NmapScanner } from '../src/agents/watchman/nmap';

jest.mock('../src/services/process', () => ({ runProcess: jest.fn() }));
jest.mock('../src/utils/logger', () => ({
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), success: jest.fn() },
}));

it('passes Nmap output paths with spaces and shell characters as a single argument', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden nmap $literal '));
    const run = jest.mocked(runProcess);
    run.mockReset();
    run.mockImplementation(async (_executable, args = []) => {
        if (args[0] === '--version')
            return { stdout: 'Nmap version 7.95', stderr: '', exitCode: 0, durationMs: 1 };
        fs.writeFileSync(args[args.indexOf('-oX') + 1], '<nmaprun></nmaprun>');
        return { stdout: '', stderr: '', exitCode: 0, durationMs: 1 };
    });
    try {
        const result = await new NmapScanner(
            { enabled: true, scanType: 'quick' },
            { url: 'https://example.invalid', authorized: true },
            directory
        ).scan();
        expect(result.summary.total).toBe(0);
        expect(run.mock.calls[1][0]).toBe('nmap');
        const args = run.mock.calls[1][1]!;
        expect(path.dirname(args[args.indexOf('-oX') + 1])).toBe(directory);
        expect(args[args.length - 1]).toBe('example.invalid');
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

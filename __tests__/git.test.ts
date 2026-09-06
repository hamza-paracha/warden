import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { GitManager } from '../src/agents/engineer/git';
import { runProcess } from '../src/services/process';

jest.mock('../src/utils/logger', () => ({ logger: { debug: jest.fn() } }));

it('handles literal commit messages and stages only declared remediation files', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden git '));
    const original = process.cwd();
    try {
        process.chdir(directory);
        await runProcess('git', ['init']);
        await runProcess('git', ['config', 'user.name', 'Warden Test']);
        await runProcess('git', ['config', 'user.email', 'test@example.invalid']);
        await runProcess('git', ['config', 'commit.gpgsign', 'false']);
        fs.writeFileSync('package.json', '{}');
        fs.writeFileSync('unrelated.txt', 'leave this alone');
        const git = new GitManager();
        await git.stageFiles(['package.json']);
        const message = 'fix: literal $(touch INJECTED) `touch INJECTED` "quotes"';
        await git.commit(message);
        expect(fs.existsSync('INJECTED')).toBe(false);
        expect((await runProcess('git', ['log', '-1', '--format=%B'])).stdout.trim()).toBe(message);
        expect((await runProcess('git', ['status', '--porcelain'])).stdout.trim()).toBe(
            '?? unrelated.txt'
        );
    } finally {
        process.chdir(original);
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

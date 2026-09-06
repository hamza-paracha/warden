import fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { saveScanResult, writeJsonAtomic } from '../src/services/artifacts';

it('preserves the previous report when replacement fails and cleans temporary files', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-artifact-'));
    try {
        const file = path.join(directory, 'report.json');
        writeJsonAtomic(file, { original: true });
        const rename = jest.spyOn(fs, 'renameSync').mockImplementationOnce(() => {
            throw new Error('disk error');
        });
        try {
            expect(() => writeJsonAtomic(file, { original: false })).toThrow('disk error');
        } finally {
            rename.mockRestore();
        }
        expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual({ original: true });
        expect(fs.readdirSync(directory)).toEqual(['report.json']);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});
it('preserves distinct history snapshots with identical timestamps', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-artifact-'));
    try {
        const result = { timestamp: '2026-09-06T00:00:00.000Z' };
        saveScanResult(result, directory);
        saveScanResult(result, directory);
        expect(fs.readdirSync(path.join(directory, 'scan-results'))).toHaveLength(3);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

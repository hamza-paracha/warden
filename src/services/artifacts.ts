import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { SCAN_RESULTS_DIR, SCAN_RESULTS_FILE } from '../constants';

/** Atomic replacement prevents readers from observing partially written JSON. */
export function writeJsonAtomic(filePath: string, value: unknown): void {
    writeTextAtomic(filePath, JSON.stringify(value, null, 2));
}

function writeTextAtomic(filePath: string, content: string): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const temporary = `${filePath}.${randomUUID()}.tmp`;
    try {
        fs.writeFileSync(temporary, content, 'utf8');
        fs.renameSync(temporary, filePath);
    } finally {
        fs.rmSync(temporary, { force: true });
    }
}

export function saveScanResult(result: { timestamp: string }, projectPath: string): void {
    const directory = path.join(projectPath, SCAN_RESULTS_DIR);
    const timestamp = result.timestamp.replace(/:/g, '-');
    const content = JSON.stringify(result, null, 2);
    writeTextAtomic(path.join(directory, `scan-${timestamp}-${randomUUID()}.json`), content);
    writeTextAtomic(path.join(directory, SCAN_RESULTS_FILE), content);
}

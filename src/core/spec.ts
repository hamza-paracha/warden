import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

export interface Spec {
    id: string;
    filename: string;
    content: string;
}

const WARDEN_HOME = path.resolve(__dirname, '../../');
const SPEC_DIR = path.join(WARDEN_HOME, 'docs/SPEC');

export function loadSpecs(): Spec[] {
    if (!fs.existsSync(SPEC_DIR)) {
        logger.warn(`SPEC directory not found at ${SPEC_DIR}.`);
        return [];
    }

    const files = fs
        .readdirSync(SPEC_DIR)
        .filter((f) => f.endsWith('.md') && f !== 'WARDEN_CORE.md');
    logger.info(`Found ${files.length} specifications.`);

    return files.map((file) => {
        const content = fs.readFileSync(path.join(SPEC_DIR, file), 'utf-8');
        return {
            id: file.replace('.md', ''),
            filename: file,
            content,
        };
    });
}

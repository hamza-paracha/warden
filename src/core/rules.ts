import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

export interface WardenRules {
    content: string;
    directives: string[];
}

// Ensure the rules are loaded from the Warden's home directory even if process.cwd() changes
const WARDEN_HOME = path.resolve(__dirname, '../../');
const RULES_FILE = path.join(WARDEN_HOME, 'docs/SPEC/WARDEN_CORE.md');

/**
 * Load and parse Warden's Rules of Engagement
 */
export function loadRules(): WardenRules {
    if (!fs.existsSync(RULES_FILE)) {
        throw new Error(`CRITICAL: Rules of Engagement file not found at ${RULES_FILE}`);
    }

    const content = fs.readFileSync(RULES_FILE, 'utf-8');
    logger.info('Rules of Engagement Loaded.');

    const directives = content.split('\n').filter((line) => line.trim().length > 0);

    return { content, directives };
}

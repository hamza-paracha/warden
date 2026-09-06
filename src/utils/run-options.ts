import { InvalidArgumentError } from 'commander';
import { SCANNER_TYPES, SEVERITY_LEVELS } from '../constants';
import { WardenOptions } from '../types';

export function parseNonNegativeInteger(value: string): number {
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
        throw new InvalidArgumentError('Expected a non-negative safe integer.');
    }
    return Number(value);
}

export function parsePositiveInteger(value: string): number {
    const number = parseNonNegativeInteger(value);
    if (number === 0 || number > 2147483647)
        throw new InvalidArgumentError('Expected an integer from 1 to 2147483647.');
    return number;
}

export function validateRunOptions(options: WardenOptions): void {
    if (!SCANNER_TYPES.includes(options.scanner))
        throw new Error(`Unsupported scanner: ${options.scanner}`);
    if (!SEVERITY_LEVELS.includes(options.minSeverity))
        throw new Error(`Invalid severity: ${options.minSeverity}`);
    if (!Number.isSafeInteger(options.maxFixes) || options.maxFixes < 0)
        throw new Error('maxFixes must be a non-negative safe integer');
    if (options.scanTimeoutMs !== undefined) parsePositiveInteger(String(options.scanTimeoutMs));
}

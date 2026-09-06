import { execFile } from 'child_process';
import { DEFAULT_TIMEOUT_MS } from '../constants';
import { logger } from '../utils/logger';

export interface ProcessOptions {
    cwd?: string;
    timeout?: number;
    maxBuffer?: number;
    env?: NodeJS.ProcessEnv;
    signal?: AbortSignal;
    log?: boolean;
    /** Scanners conventionally return 1 when findings are present. */
    allowedExitCodes?: readonly number[];
}

export interface ProcessResult {
    stdout: string;
    stderr: string;
    exitCode: number;
    durationMs: number;
}

export class ProcessError extends Error {
    constructor(
        public readonly executable: string,
        public readonly code: string | number,
        public readonly stdout: string,
        public readonly stderr: string,
        public readonly killed: boolean,
        public readonly signal: string | null,
        message: string
    ) {
        super(`${executable} failed (${code}): ${message}`);
        this.name = 'ProcessError';
    }
}

/** Execute an argument vector without shell interpolation, with bounded time and output. */
export function runProcess(
    executable: string,
    args: readonly string[] = [],
    options: ProcessOptions = {}
): Promise<ProcessResult> {
    const {
        allowedExitCodes = [0],
        log = true,
        timeout = DEFAULT_TIMEOUT_MS,
        maxBuffer = 10 * 1024 * 1024,
        ...executionOptions
    } = options;
    if (log) logger.debug(`Executing ${executable}`);
    const start = performance.now();
    return new Promise((resolve, reject) => {
        execFile(
            executable,
            [...args],
            {
                timeout,
                maxBuffer,
                ...executionOptions,
                encoding: 'utf8',
                shell: false,
            },
            (error, stdout, stderr) => {
                const exitCode = error ? error.code : 0;
                // Never accept partial output after a timeout, cancellation, or buffer overflow.
                if (
                    error &&
                    (error.killed ||
                        error.signal ||
                        typeof exitCode !== 'number' ||
                        !allowedExitCodes.includes(exitCode))
                ) {
                    reject(
                        new ProcessError(
                            executable,
                            exitCode ?? 'UNKNOWN',
                            stdout,
                            stderr,
                            error.killed ?? false,
                            error.signal ?? null,
                            error.message
                        )
                    );
                    return;
                }
                resolve({
                    stdout,
                    stderr,
                    exitCode: exitCode as number,
                    durationMs: performance.now() - start,
                });
            }
        );
    });
}

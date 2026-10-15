import * as winston from 'winston';
import chalk from 'chalk';

export enum LogLevel {
    ERROR = 'error',
    WARN = 'warn',
    INFO = 'info',
    DEBUG = 'debug',
}

class Logger {
    private winstonLogger?: winston.Logger;
    private verboseMode: boolean = false;
    private quietMode: boolean = false;

    /**
     * Format duration in human-readable format
     */
    private formatDuration(ms: number): string {
        if (ms < 1000) {
            return `${ms}ms`;
        }
        const seconds = Math.floor(ms / 1000);
        if (seconds < 60) {
            return `${seconds}s`;
        }
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}m ${remainingSeconds}s`;
    }

    // Importing the CLI must not create logs in a repository being verified.
    private getLogger(): winston.Logger {
        if (this.winstonLogger) return this.winstonLogger;
        this.winstonLogger = winston.createLogger({
            level: this.verboseMode ? 'debug' : 'info',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            transports: [
                new winston.transports.File({
                    filename: 'warden-error.log',
                    level: 'error',
                    dirname: 'logs',
                }),
                new winston.transports.File({
                    filename: 'warden-combined.log',
                    dirname: 'logs',
                }),
            ],
        });
        return this.winstonLogger;
    }

    setVerbose(verbose: boolean) {
        this.verboseMode = verbose;
        if (this.winstonLogger) this.winstonLogger.level = verbose ? 'debug' : 'info';
    }

    setQuiet(quiet: boolean) {
        this.quietMode = quiet;
    }

    isQuiet(): boolean {
        return this.quietMode;
    }

    private formatMessage(level: string, message: string, prefix?: string): string {
        const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
        const prefixStr = prefix ? `${prefix} | ` : '';

        switch (level) {
            case 'error':
                return chalk.red(`[${timestamp}] [ERROR] ${prefixStr}${message}`);
            case 'warn':
                return chalk.yellow(`[${timestamp}] [WARN] ${prefixStr}${message}`);
            case 'info':
                return chalk.blue(`[${timestamp}] [INFO] ${prefixStr}${message}`);
            case 'debug':
                return chalk.gray(`[${timestamp}] [DEBUG] ${prefixStr}${message}`);
            case 'success':
                return chalk.green(`[${timestamp}] [SUCCESS] ${prefixStr}${message}`);
            default:
                return `[${timestamp}] ${prefixStr}${message}`;
        }
    }

    error(message: string, error?: Error, prefix?: string) {
        const formattedMsg = this.formatMessage('error', message, prefix);
        // Errors are always shown, even in quiet mode
        console.error(formattedMsg);

        if (error) {
            console.error(chalk.red(error.stack || error.message));
            this.getLogger().error(message, { error: error.message, stack: error.stack });
        } else {
            this.getLogger().error(message);
        }
    }

    warn(message: string, prefix?: string) {
        const formattedMsg = this.formatMessage('warn', message, prefix);
        if (!this.quietMode) {
            console.warn(formattedMsg);
        }
        this.getLogger().warn(message);
    }

    info(message: string, prefix?: string) {
        const formattedMsg = this.formatMessage('info', message, prefix);
        if (!this.quietMode) {
            console.log(formattedMsg);
        }
        this.getLogger().info(message);
    }

    debug(message: string, prefix?: string) {
        if (this.verboseMode && !this.quietMode) {
            const formattedMsg = this.formatMessage('debug', message, prefix);
            console.log(formattedMsg);
        }
        this.getLogger().debug(message);
    }

    success(message: string, prefix?: string) {
        const formattedMsg = this.formatMessage('success', message, prefix);
        if (!this.quietMode) {
            console.log(formattedMsg);
        }
        this.getLogger().info(`SUCCESS: ${message}`);
    }

    // Agent-specific loggers
    watchman(message: string) {
        this.info(message, '🔍 WATCHMAN');
    }

    engineer(message: string) {
        this.info(message, '🔧 ENGINEER');
    }

    diplomat(message: string) {
        this.info(message, '🤝 DIPLOMAT');
    }

    // Special formatting for headers
    header(message: string) {
        if (!this.quietMode) {
            console.log('\n' + chalk.bold.blue(message));
            console.log(chalk.blue('─'.repeat(message.length)) + '\n');
        }
    }

    section(message: string) {
        if (!this.quietMode) {
            console.log('\n' + chalk.blue('• ') + chalk.bold.white(message));
        }
    }

    timing(label: string, ms: number) {
        const formatted = this.formatDuration(ms);
        this.info(`${label}: ${formatted}`);
    }
}

// Singleton instance
export const logger = new Logger();

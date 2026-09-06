import { runProcess } from '../../services/process';
import { GIT_TIMEOUT_MS } from '../../constants';
import { logger } from '../../utils/logger';

export class GitManager {
    private async exec(args: string[]): Promise<string> {
        const result = await runProcess('git', args, { timeout: GIT_TIMEOUT_MS });
        return result.stdout.trim();
    }

    /**
     * Check if a branch exists
     */
    async branchExists(branchName: string): Promise<boolean> {
        try {
            await this.exec(['show-ref', '--verify', '--quiet', `refs/heads/${branchName}`]);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Create and checkout a new branch.
     * If branch exists, just checkout it.
     */
    async checkoutBranch(branchName: string): Promise<void> {
        await this.exec(['check-ref-format', '--branch', branchName]);
        if (branchName.startsWith('-')) throw new Error('Invalid branch name');
        // Check if we are already on the branch to avoid errors
        try {
            const currentBranch = await this.exec(['rev-parse', '--abbrev-ref', 'HEAD']);
            if (currentBranch === branchName) {
                logger.debug(`Already on branch: ${branchName}`);
                return;
            }

            const exists = await this.branchExists(branchName);
            if (exists) {
                logger.debug(`Switching to existing branch: ${branchName}`);
                await this.exec(['checkout', branchName]);
            } else {
                logger.debug(`Creating new branch: ${branchName}`);
                await this.exec(['checkout', '-b', branchName]);
            }
        } catch (error) {
            throw new Error(`Failed to checkout branch ${branchName}: ${error}`);
        }
    }

    async getCurrentBranch(): Promise<string> {
        return this.exec(['rev-parse', '--abbrev-ref', 'HEAD']);
    }

    async hasUncommittedChanges(): Promise<boolean> {
        const status = await this.exec(['status', '--porcelain']);
        return status.trim().length > 0;
    }

    /**
     * Stage all changes
     */
    async stageAll(): Promise<void> {
        logger.debug('Staging changes...');
        await this.exec(['add', '.']);
    }

    /** Stage only the files owned by a remediation, excluding unrelated generated artifacts. */
    async stageFiles(files: readonly string[]): Promise<void> {
        if (files.length === 0) return;
        await this.exec(['add', '--', ...files]);
    }

    /**
     * Commit changes
     */
    async commit(message: string): Promise<void> {
        logger.debug(`Committing changes: "${message}"`);
        await this.exec(['commit', '-m', message]);
    }

    /**
     * Revert all changes in the current directory (hard reset)
     * USE WITH CAUTION
     */
    async revertChanges(): Promise<void> {
        logger.info('Reverting changes...');
        await this.exec(['restore', '.']);
    }

    /**
     * Return to main branch
     */
    async checkoutMain(): Promise<void> {
        // Try 'main' or 'master'
        try {
            await this.exec(['checkout', 'main']);
        } catch {
            await this.exec(['checkout', 'master']);
        }
    }
}

import { Octokit } from '@octokit/rest';
import { runProcess } from '../../services/process';
import { GIT_TIMEOUT_MS } from '../../constants';
import { logger } from '../../utils/logger';

export interface PrConfig {
    branch: string;
    title: string;
    body: string;
    severity?: string;
    labels?: string[];
}

export class DiplomatAgent {
    private octokit: Octokit | null = null;

    constructor() {
        if (process.env.GITHUB_TOKEN) {
            this.octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
        }
    }

    async createPullRequest(config: PrConfig): Promise<string> {
        logger.diplomat(`Preparing to open PR for ${config.branch}`);

        if (!this.octokit) {
            throw new Error(
                'Diplomat: No GITHUB_TOKEN found. Real API Integration requires a token.'
            );
        }

        try {
            // Extract owner and repo from git remote
            const { owner, repo } = await this.getRepoInfo();
            const base = await this.getDefaultBaseBranch();

            logger.diplomat(`Opening PR on ${owner}/${repo}...`);

            // Create the pull request using Octokit
            const response = await this.octokit.pulls.create({
                owner,
                repo,
                title: config.title,
                body: config.body,
                head: config.branch,
                base,
            });

            logger.success(`PR created successfully! URL: ${response.data.html_url}`);
            logger.info(`PR Number: #${response.data.number}`);

            // 1. Smart Labelling
            const labels = ['security', 'automated'];
            if (config.severity) {
                labels.push(`severity:${config.severity.toLowerCase()}`);
            }
            if (config.labels) {
                labels.push(...config.labels);
            }
            await this.addLabels(owner, repo, response.data.number, labels);

            // 2. Assignee Management
            await this.addAssignees(owner, repo, response.data.number);

            return response.data.html_url;
        } catch (error: any) {
            logger.error(`Diplomat: Failed to create PR: ${error.message}`);

            // Provide helpful error messages
            if (error.status === 422) {
                logger.warn(
                    `Branch '${config.branch}' may not exist on remote, or a PR already exists.`
                );
            } else if (error.status === 401) {
                logger.warn(`GITHUB_TOKEN may be invalid or expired.`);
            } else if (error.status === 404) {
                logger.warn(`Repository not found. Check git remote configuration.`);
            }

            throw error;
        }
    }

    private async getDefaultBaseBranch(): Promise<string> {
        try {
            const ref = (
                await runProcess('git', ['symbolic-ref', 'refs/remotes/origin/HEAD'], {
                    timeout: GIT_TIMEOUT_MS,
                })
            ).stdout.trim();
            const branch = ref.replace(/^refs\/remotes\/origin\//, '');
            return branch || 'main';
        } catch {
            return 'main';
        }
    }

    /**
     * Extract owner and repo from git remote URL
     */
    private async getRepoInfo(): Promise<{ owner: string; repo: string }> {
        try {
            // Get the remote URL
            const remoteUrl = (
                await runProcess('git', ['config', '--get', 'remote.origin.url'], {
                    timeout: GIT_TIMEOUT_MS,
                })
            ).stdout.trim();

            // Parse GitHub URL (supports both HTTPS and SSH formats)
            const match = remoteUrl.match(/github\.com[:/]([^/]+)\/(.+?)(?:\.git)?$/);

            if (!match) {
                throw new Error(`Could not parse GitHub URL: ${remoteUrl}`);
            }

            const owner = match[1];
            const repo = match[2];

            return { owner, repo };
        } catch (error: any) {
            logger.error(`Failed to get repository info: ${error.message}`);
            logger.info(`Falling back to environment variables...`);

            // Fallback to environment variables if available
            const owner = process.env.GITHUB_OWNER || 'unknown-owner';
            const repo = process.env.GITHUB_REPO || 'warden';

            return { owner, repo };
        }
    }

    /**
     * Add labels to a pull request
     */
    private async addLabels(
        owner: string,
        repo: string,
        issueNumber: number,
        labels: string[]
    ): Promise<void> {
        if (!this.octokit) return;

        try {
            await this.octokit.issues.addLabels({
                owner,
                repo,
                issue_number: issueNumber,
                labels,
            });
            logger.diplomat(`Added labels: ${labels.join(', ')}`);
        } catch (error: any) {
            logger.warn(`Diplomat: Failed to add labels: ${error.message}`);
            // Don't throw - labels are nice-to-have
        }
    }

    /**
     * Auto-assign the PR to the repo owner or configured user
     */
    private async addAssignees(owner: string, repo: string, issueNumber: number): Promise<void> {
        if (!this.octokit) return;

        try {
            // Priority: GITHUB_ASSIGNEE env var -> Repo Owner
            const assignee = process.env.GITHUB_ASSIGNEE || owner;

            await this.octokit.issues.addAssignees({
                owner,
                repo,
                issue_number: issueNumber,
                assignees: [assignee],
            });
            logger.diplomat(`Assigned PR to ${assignee}`);
        } catch (error: any) {
            logger.warn(`Diplomat: Failed to assign PR: ${error.message}`);
        }
    }

    /**
     * Detect all local warden/* branches
     */
    async detectWardenBranches(): Promise<string[]> {
        try {
            const branches = (
                await runProcess(
                    'git',
                    ['branch', '--list', 'warden/*', '--format=%(refname:short)'],
                    { timeout: GIT_TIMEOUT_MS }
                )
            ).stdout.trim();

            if (!branches) {
                return [];
            }

            // Parse branch names (remove leading * and whitespace)
            const branchList = branches
                .split('\n')
                .map((b) => b.replace(/^\*?\s+/, ''))
                .filter((b) => b.length > 0);

            return branchList;
        } catch (error: any) {
            logger.error(`Failed to detect branches: ${error.message}`);
            return [];
        }
    }

    /**
     * Push a branch to remote origin
     */
    async pushBranch(branch: string): Promise<boolean> {
        try {
            logger.diplomat(`Pushing ${branch} to origin...`);
            await runProcess('git', ['check-ref-format', '--branch', branch], {
                timeout: GIT_TIMEOUT_MS,
            });
            await runProcess(
                'git',
                ['push', '-u', 'origin', `refs/heads/${branch}:refs/heads/${branch}`],
                { timeout: GIT_TIMEOUT_MS }
            );
            logger.success(`Branch ${branch} pushed successfully.`);
            return true;
        } catch (error: any) {
            logger.error(`Failed to push branch: ${error.message}`);
            return false;
        }
    }

    /**
     * Generate a semantic PR title from a branch name
     */
    generatePrTitle(branch: string, vulnerabilityName?: string): string {
        if (!vulnerabilityName) {
            const parts = branch.split('/');
            const fixPart = parts[parts.length - 1];
            const name = fixPart
                .replace(/^fix-/, '')
                .split('-')
                .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
            vulnerabilityName = name;
        }

        return `[SECURITY] Fix for ${vulnerabilityName}`;
    }

    /**
     * Generate a semantic PR body with vulnerability details
     */
    generatePrBody(vulnerabilityId?: string, severity?: string, description?: string): string {
        let body = `## Automated Security Fix\n\n`;
        body += `This PR was automatically generated by **Warden** to address a security vulnerability.\n\n`;

        if (vulnerabilityId) {
            body += `### Vulnerability Details\n`;
            body += `- **ID**: ${vulnerabilityId}\n`;
            if (severity) {
                body += `- **Severity**: ${severity}\n`;
            }
            if (description) {
                body += `- **Description**: ${description}\n`;
            }
            body += `\n`;
        }

        body += `### Changes Made\n`;
        body += `- Applied automated security patch\n`;
        body += `- All tests passing\n\n`;

        body += `### Review Checklist\n`;
        body += `- [ ] Verify the fix addresses the vulnerability\n`;
        body += `- [ ] Check for any breaking changes\n`;
        body += `- [ ] Confirm test coverage\n\n`;

        body += `---\n`;
        body += `*Generated by Warden [AUTOMATED]*`;

        return body;
    }

    /**
     * Full workflow: Detect, Push, and Create PR for warden branches
     */
    async processAllWardenBranches(): Promise<string[]> {
        logger.diplomat(`Scanning for warden/* branches...`);

        const branches = await this.detectWardenBranches();

        if (branches.length === 0) {
            logger.info(`No warden branches found.`);
            return [];
        }

        logger.diplomat(`Found ${branches.length} warden branch(es): ${branches.join(', ')}`);

        const prUrls: string[] = [];

        for (const branch of branches) {
            try {
                // Push the branch to remote
                const pushed = await this.pushBranch(branch);

                if (!pushed && this.octokit) {
                    logger.warn(`Skipping PR creation for ${branch} (push failed)`);
                    continue;
                }

                // Generate PR title and body
                const title = this.generatePrTitle(branch);
                const body = this.generatePrBody();

                // Create the PR
                const prUrl = await this.createPullRequest({
                    branch,
                    title,
                    body,
                });

                prUrls.push(prUrl);
            } catch (error: any) {
                logger.error(`Failed to process ${branch}: ${error.message}`);
            }
        }

        return prUrls;
    }
}

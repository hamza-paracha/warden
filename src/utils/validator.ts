import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from './logger';

export interface ValidationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
}

export type ProjectType = 'node' | 'python' | 'unknown';

export class Validator {
    /**
     * Create a new validation result
     */
    private createResult(valid: boolean = true): ValidationResult {
        return {
            valid,
            errors: [],
            warnings: [],
        };
    }

    /**
     * Sanitize repository URL
     * Ensures the repo string is clean, valid, and follows expected formats
     */
    sanitizeRepositoryUrl(repo: string): string | null {
        if (!repo || typeof repo !== 'string') {
            return null;
        }

        // Trim whitespace
        const trimmed = repo.trim();

        // Patterns to match (in order of priority):
        // - https://github.com/owner/repo
        // - https://github.com/owner/repo.git
        // - git@github.com:owner/repo.git
        // - github.com/owner/repo
        // - owner/repo (shorthand)
        // - local paths

        try {
            // Handle git@ SSH format
            if (trimmed.startsWith('git@')) {
                const sshMatch = trimmed.match(/git@github\.com:([^/]+)\/([^/.]+)(\.git)?$/);
                if (sshMatch) {
                    const [, owner, repo] = sshMatch;
                    return `https://github.com/${owner}/${repo}`;
                }
                return null;
            }

            // Handle HTTPS URLs
            if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
                const url = new URL(trimmed);

                // Only support GitHub for now
                if (!url.hostname.includes('github.com')) {
                    return null;
                }

                // Extract owner/repo from pathname
                const pathParts = url.pathname.split('/').filter((p) => p.length > 0);
                if (pathParts.length >= 2) {
                    const owner = pathParts[0];
                    const repo = pathParts[1].replace(/\.git$/, '');
                    return `https://github.com/${owner}/${repo}`;
                }
                return null;
            }

            // Handle github.com/owner/repo format
            if (trimmed.startsWith('github.com/')) {
                const parts = trimmed.replace('github.com/', '').split('/');
                if (parts.length >= 2) {
                    const owner = parts[0];
                    const repo = parts[1].replace(/\.git$/, '');
                    return `https://github.com/${owner}/${repo}`;
                }
                return null;
            }

            // Handle owner/repo shorthand - must match GitHub repo pattern (no spaces or special chars)
            const shorthandMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)$/);
            if (shorthandMatch) {
                const [, owner, repo] = shorthandMatch;
                return `https://github.com/${owner}/${repo.replace(/\.git$/, '')}`;
            }

            // If it's a local file path, return as-is
            // Check for path-like characteristics: starts with ./ or / or ~
            if (
                trimmed.startsWith('./') ||
                trimmed.startsWith('../') ||
                trimmed.startsWith('/') ||
                trimmed.startsWith('~')
            ) {
                return trimmed;
            }

            // If none of the patterns match, return null
            return null;
        } catch (error) {
            return null;
        }
    }

    /**
     * Validate repository URL
     * Returns a ValidationResult with detailed errors/warnings
     */
    validateRepositoryUrl(repo: string): ValidationResult {
        const result = this.createResult();

        if (!repo || typeof repo !== 'string') {
            result.errors.push('Repository URL cannot be empty');
            result.valid = false;
            return result;
        }

        // Check for spaces in original input
        if (repo.includes(' ')) {
            result.errors.push('Repository URL cannot contain spaces');
            result.valid = false;
            return result;
        }

        const sanitized = this.sanitizeRepositoryUrl(repo);
        if (!sanitized) {
            result.errors.push(`Invalid repository format: ${repo}`);
            result.errors.push(
                'Expected formats: https://github.com/owner/repo, git@github.com:owner/repo.git, or owner/repo'
            );
            result.valid = false;
            return result;
        }

        if (sanitized.length > 500) {
            result.errors.push('Repository URL is too long');
            result.valid = false;
        }

        return result;
    }

    /**
     * Validate branch name
     * Ensures fix branches follow consistent and safe naming conventions
     */
    validateBranchName(branchName: string): ValidationResult {
        const result = this.createResult();

        if (!branchName || typeof branchName !== 'string') {
            result.errors.push('Branch name cannot be empty');
            result.valid = false;
            return result;
        }

        const trimmed = branchName.trim();

        // Length check
        if (trimmed.length === 0) {
            result.errors.push('Branch name cannot be empty');
            result.valid = false;
            return result;
        }

        if (trimmed.length > 255) {
            result.errors.push('Branch name is too long (max 255 characters)');
            result.valid = false;
        }

        // Git branch name rules
        // Cannot start or end with /
        if (trimmed.startsWith('/') || trimmed.endsWith('/')) {
            result.errors.push('Branch name cannot start or end with /');
            result.valid = false;
        }

        // Cannot contain ..
        if (trimmed.includes('..')) {
            result.errors.push('Branch name cannot contain ".."');
            result.valid = false;
        }

        // Cannot contain control characters or spaces
        if (/[\x00-\x1f\x7f ]/.test(trimmed)) {
            result.errors.push('Branch name cannot contain control characters or spaces');
            result.valid = false;
        }

        // Cannot contain special characters that git doesn't allow
        if (/[~^:?*\[\\]/.test(trimmed)) {
            result.errors.push('Branch name cannot contain ~, ^, :, ?, *, [, \\, or ]');
            result.valid = false;
        }

        // Cannot be just @ or end with .lock
        if (trimmed === '@' || trimmed.endsWith('.lock')) {
            result.errors.push('Invalid branch name format');
            result.valid = false;
        }

        // Warden-specific validation for fix branches
        if (trimmed.startsWith('warden/')) {
            // Check format: warden/fix-{package-name} or warden/{type}-{description}
            const wardenPattern = /^warden\/(fix|feat|chore|docs|refactor|test)-[a-zA-Z0-9._-]+$/;
            if (!wardenPattern.test(trimmed)) {
                result.warnings.push(
                    'Warden branch should follow format: warden/{type}-{description}'
                );
                result.warnings.push('Valid types: fix, feat, chore, docs, refactor, test');
            }

            // Check for double slashes
            if (trimmed.includes('//')) {
                result.errors.push('Branch name cannot contain consecutive slashes');
                result.valid = false;
            }
        }

        return result;
    }

    /**
     * Sanitize branch name
     * Converts an arbitrary string into a safe git branch name
     */
    sanitizeBranchName(branchName: string, prefix: string = 'warden/fix'): string {
        if (!branchName || typeof branchName !== 'string') {
            return `${prefix}-unknown`;
        }

        // Remove control characters and spaces
        let sanitized = branchName
            .trim()
            .replace(/[\x00-\x1f\x7f ]/g, '-')
            .replace(/[~^:?*\[\\]/g, '-')
            .replace(/\.lock$/g, '')
            .replace(/^@/, 'at-')
            .replace(/^\/+|\/+$/g, '');

        // Handle slashes - if it already has warden/, preserve structure
        // Otherwise replace slashes with hyphens
        if (!sanitized.startsWith('warden/')) {
            sanitized = sanitized.replace(/\//g, '-');
        }

        // Clean up other patterns
        sanitized = sanitized.replace(/\.\.+/g, '.').replace(/-+/g, '-').toLowerCase();

        // Ensure it doesn't exceed length
        const maxDescLength = 200;
        if (sanitized.length > maxDescLength) {
            sanitized = sanitized.substring(0, maxDescLength);
        }

        // Remove trailing dots or hyphens
        sanitized = sanitized.replace(/[.-]+$/, '');

        // If it starts with warden/, keep it; otherwise add prefix
        if (!sanitized.startsWith('warden/')) {
            sanitized = `${prefix}-${sanitized}`;
        }

        return sanitized;
    }

    /**
     * Check if a command exists in the system PATH
     */
    private commandExists(command: string): boolean {
        try {
            execSync(`which ${command}`, { stdio: 'pipe' });
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Validate environment variables
     */
    validateEnvironment(): ValidationResult {
        const result = this.createResult();

        // Check for .env file
        const envPath = path.resolve(process.cwd(), '.env');
        if (!fs.existsSync(envPath)) {
            result.warnings.push('.env file not found. Using system environment variables.');
        }

        // Required for GitHub operations
        if (!process.env.GITHUB_TOKEN) {
            result.warnings.push('GITHUB_TOKEN is not set; pull request creation will be skipped');
        }

        // Optional but recommended
        if (!process.env.SNYK_TOKEN) {
            result.warnings.push(
                'SNYK_TOKEN not set. Snyk may require authentication for some features.'
            );
        }

        if (!process.env.GITHUB_OWNER) {
            result.warnings.push('GITHUB_OWNER not set. Will attempt to detect from git remote.');
        }

        if (!process.env.GITHUB_REPO) {
            result.warnings.push('GITHUB_REPO not set. Will attempt to detect from git remote.');
        }

        return result;
    }

    /**
     * Validate required system dependencies
     */
    validateDependencies(): ValidationResult {
        const result = this.createResult();

        // Check for Git
        if (!this.commandExists('git')) {
            result.errors.push('Git is not installed or not in PATH');
            result.valid = false;
        }

        // Check for Node.js (should always exist if we're running)
        if (!this.commandExists('node')) {
            result.errors.push('Node.js is not installed or not in PATH');
            result.valid = false;
        }

        // Check for npm
        if (!this.commandExists('npm')) {
            result.warnings.push('npm is not installed or not in PATH');
        }

        if (!this.commandExists('python3')) {
            result.warnings.push('python3 is not installed or not in PATH');
        }

        if (!this.commandExists('pip-audit')) {
            result.warnings.push(
                'pip-audit is not installed. Install with: python3 -m pip install pip-audit'
            );
        }

        // Check for Snyk (optional but recommended)
        if (!this.commandExists('snyk')) {
            result.warnings.push('Snyk CLI is not installed. Install with: npm install -g snyk');
            result.warnings.push('Fallback to npm audit will be used if Snyk is unavailable.');
        }

        // Check for GitHub CLI (optional)
        if (!this.commandExists('gh')) {
            result.warnings.push('GitHub CLI (gh) is not installed. Some features may be limited.');
        }

        return result;
    }

    /**
     * Validate Git repository
     */
    validateGitRepository(targetPath: string = process.cwd()): ValidationResult {
        const result = this.createResult();

        const gitDir = path.join(targetPath, '.git');

        if (!fs.existsSync(gitDir)) {
            result.errors.push(`Not a git repository: ${targetPath}`);
            result.valid = false;
            return result;
        }

        try {
            // Check if we have a remote
            const remotes = execSync('git remote -v', {
                cwd: targetPath,
                stdio: 'pipe',
                encoding: 'utf-8',
            });

            if (!remotes || remotes.trim().length === 0) {
                result.warnings.push('No git remotes configured. PR creation may fail.');
            }

            // Check for uncommitted changes
            const status = execSync('git status --porcelain', {
                cwd: targetPath,
                stdio: 'pipe',
                encoding: 'utf-8',
            });

            if (status && status.trim().length > 0) {
                result.warnings.push(
                    'Repository has uncommitted changes. These will not be included in automated fixes.'
                );
            }
        } catch (error: any) {
            result.errors.push(`Git validation failed: ${error.message}`);
            result.valid = false;
        }

        return result;
    }

    /**
     * Detect primary project type from local manifests
     */
    detectProjectType(targetPath: string = process.cwd()): ProjectType {
        if (fs.existsSync(path.join(targetPath, 'package.json'))) {
            return 'node';
        }

        if (
            fs.existsSync(path.join(targetPath, 'requirements.txt')) ||
            fs.existsSync(path.join(targetPath, 'pyproject.toml'))
        ) {
            return 'python';
        }

        return 'unknown';
    }

    /**
     * Validate supported project manifests
     */
    validateProjectManifest(targetPath: string = process.cwd()): ValidationResult {
        const result = this.createResult();

        const projectType = this.detectProjectType(targetPath);
        if (projectType === 'node') {
            const packageJsonPath = path.join(targetPath, 'package.json');

            try {
                const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));

                if (!packageJson.dependencies && !packageJson.devDependencies) {
                    result.warnings.push('No dependencies found in package.json');
                }

                if (!packageJson.scripts || !packageJson.scripts.test) {
                    result.warnings.push(
                        'No test script found in package.json. Verification will be skipped.'
                    );
                }
            } catch (error: any) {
                result.errors.push(`Invalid package.json: ${error.message}`);
                result.valid = false;
            }

            return result;
        }

        if (projectType === 'python') {
            const requirementsPath = path.join(targetPath, 'requirements.txt');
            const pyprojectPath = path.join(targetPath, 'pyproject.toml');

            if (fs.existsSync(requirementsPath)) {
                const content = fs.readFileSync(requirementsPath, 'utf-8');
                if (!content.trim()) {
                    result.warnings.push('requirements.txt is empty');
                }
                if (!fs.existsSync(path.join(targetPath, 'tests'))) {
                    result.warnings.push(
                        'No tests/ directory found. Python verification may be skipped.'
                    );
                }
            } else if (fs.existsSync(pyprojectPath)) {
                result.warnings.push(
                    'pyproject.toml detected, but auto-remediation currently requires requirements.txt for Python projects.'
                );
            }

            return result;
        }

        result.errors.push(
            'No supported manifest found. Warden currently supports package.json or requirements.txt-based projects.'
        );
        result.valid = false;
        return result;
    }

    /**
     * Run all validations
     */
    validateAll(targetPath: string = process.cwd()): ValidationResult {
        logger.debug('Running comprehensive validation...');

        const results: ValidationResult[] = [
            this.validateEnvironment(),
            this.validateDependencies(),
            this.validateGitRepository(targetPath),
            this.validateProjectManifest(targetPath),
        ];

        const combined = this.createResult();

        for (const result of results) {
            if (!result.valid) {
                combined.valid = false;
            }
            combined.errors.push(...result.errors);
            combined.warnings.push(...result.warnings);
        }

        return combined;
    }

    /**
     * Print validation results
     */
    printValidationResults(result: ValidationResult) {
        if (result.errors.length > 0) {
            logger.error('Validation failed with the following errors:');
            result.errors.forEach((err) => logger.error(`  ✗ ${err}`));
        }

        if (result.warnings.length > 0) {
            logger.warn('Validation warnings:');
            result.warnings.forEach((warn) => logger.warn(`  ⚠ ${warn}`));
        }

        if (result.valid && result.errors.length === 0) {
            logger.success('All validations passed!');
        }
    }
}

export const validator = new Validator();

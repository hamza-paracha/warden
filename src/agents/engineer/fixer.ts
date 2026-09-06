/**
 * Fixer Abstraction Layer
 *
 * Decouples the EngineerAgent from npm/Node.js specifics.
 * Defines the IFixer interface and provides NpmFixer as the default
 * implementation. Future package managers (pip, cargo, etc.) can be
 * added by implementing IFixer without touching EngineerAgent.
 */

import * as fs from 'fs';
import * as path from 'path';
import { GitManager } from './git';
import { runCommand } from '../../services/shell';
import { logger } from '../../utils/logger';
import { validator } from '../../utils/validator';
import { FixInstruction } from '../../types';
import { DEFAULT_BRANCH_PREFIX } from '../../constants';

// ─────────────────────────────────────────────────────────────────────────────
// Interface
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A Fixer encapsulates all package-manager-specific logic needed to apply a
 * security fix: branch creation, manifest update, lock-file refresh, and
 * verification.
 */
export interface IFixer {
    /** Human-readable identifier, e.g. 'npm', 'pip', 'cargo' */
    readonly name: string;

    /**
     * Return true when this fixer is capable of handling the given instruction
     * (e.g. NpmFixer checks that package.json exists and contains the package).
     */
    canFix(instruction: FixInstruction): boolean;

    /**
     * Apply the fix described by `instruction`.
     *
     * @param instruction  The structured update to apply.
     * @param vulnerabilityId  ID used in the commit message.
     * @param branchPrefix  Prefix for the git branch (default: DEFAULT_BRANCH_PREFIX).
     * @returns true on success, false on recoverable failure.
     */
    applyFix(
        instruction: FixInstruction,
        vulnerabilityId: string,
        branchPrefix?: string
    ): Promise<boolean>;
}

// ─────────────────────────────────────────────────────────────────────────────
// NpmFixer
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Applies security fixes to Node.js / npm projects.
 *
 * Steps:
 *  1. Derive & validate a git branch name
 *  2. Checkout (or create) the branch
 *  3. Update the version in package.json (dependencies / devDependencies)
 *  4. Run `npm install` to regenerate the lock-file
 *  5. Run `npm test` for verification
 *  6. On success: stage all changes and commit
 *  7. On test failure: revert all changes and return false
 */
export class NpmFixer implements IFixer {
    readonly name = 'npm';

    private git: GitManager;

    constructor() {
        this.git = new GitManager();
    }

    private getDependencySpec(currentSpec: string, targetVersion: string): string {
        if (currentSpec.startsWith('workspace:')) {
            return currentSpec;
        }

        const prefix = currentSpec.match(/^[~^]/)?.[0] || '';
        return `${prefix}${targetVersion}`;
    }

    private hasTestScript(): boolean {
        const packageJsonPath = path.resolve(process.cwd(), 'package.json');

        try {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
            return Boolean(packageJson.scripts?.test);
        } catch {
            return false;
        }
    }

    private restoreFileSnapshot(
        filePath: string,
        originalContent: string | null,
        existedInitially: boolean
    ): void {
        if (!existedInitially) {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
            return;
        }

        if (originalContent !== null) {
            fs.writeFileSync(filePath, originalContent, 'utf-8');
        }
    }

    // ── canFix ──────────────────────────────────────────────────────────────

    canFix(instruction: FixInstruction): boolean {
        const pkgJsonPath = path.resolve(process.cwd(), 'package.json');

        if (!fs.existsSync(pkgJsonPath)) {
            return false;
        }

        try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
            return (
                (pkg.dependencies && pkg.dependencies[instruction.packageName] !== undefined) ||
                (pkg.devDependencies && pkg.devDependencies[instruction.packageName] !== undefined)
            );
        } catch {
            return false;
        }
    }

    // ── applyFix ─────────────────────────────────────────────────────────────

    async applyFix(
        instruction: FixInstruction,
        vulnerabilityId: string,
        branchPrefix: string = DEFAULT_BRANCH_PREFIX
    ): Promise<boolean> {
        const { packageName, targetVersion } = instruction;

        logger.engineer(`Applying npm fix: ${packageName} → ${targetVersion}`);

        // 1. Derive & validate branch name
        let branchName = `${branchPrefix}-${packageName}`;
        const branchValidation = validator.validateBranchName(branchName);

        if (!branchValidation.valid) {
            logger.warn('Branch name validation failed, sanitizing...');
            branchName = validator.sanitizeBranchName(packageName, branchPrefix);
            logger.info(`Sanitized branch name: ${branchName}`);
        } else if (branchValidation.warnings.length > 0) {
            branchValidation.warnings.forEach((w) => logger.warn(w));
        }

        try {
            if (await this.git.hasUncommittedChanges()) {
                logger.error(
                    'Refusing to auto-fix with uncommitted changes present. Commit or stash changes first.'
                );
                return false;
            }

            // 2. Checkout branch
            await this.git.checkoutBranch(branchName);

            // 3. Update package.json
            const packageJsonPath = path.resolve(process.cwd(), 'package.json');
            const packageLockPath = path.resolve(process.cwd(), 'package-lock.json');
            if (!fs.existsSync(packageJsonPath)) {
                throw new Error('package.json not found');
            }

            const originalPackageJson = fs.readFileSync(packageJsonPath, 'utf-8');
            const packageLockExisted = fs.existsSync(packageLockPath);
            const originalPackageLock = packageLockExisted
                ? fs.readFileSync(packageLockPath, 'utf-8')
                : null;
            const packageJson = JSON.parse(originalPackageJson);
            let updated = false;

            if (packageJson.dependencies?.[packageName] !== undefined) {
                logger.info(
                    `Updating dependencies: ${packageName} ` +
                        `${packageJson.dependencies[packageName]} → ${targetVersion}`
                );
                packageJson.dependencies[packageName] = this.getDependencySpec(
                    packageJson.dependencies[packageName],
                    targetVersion
                );
                updated = true;
            }

            if (packageJson.devDependencies?.[packageName] !== undefined) {
                logger.info(
                    `Updating devDependencies: ${packageName} ` +
                        `${packageJson.devDependencies[packageName]} → ${targetVersion}`
                );
                packageJson.devDependencies[packageName] = this.getDependencySpec(
                    packageJson.devDependencies[packageName],
                    targetVersion
                );
                updated = true;
            }

            if (!updated) {
                logger.error(
                    `Package "${packageName}" not found in dependencies or devDependencies. ` +
                        'This may be a transitive dependency.'
                );
                return false;
            }

            fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));

            // 4. Regenerate lock-file
            logger.engineer('Running npm install --package-lock-only to update lock-file...');
            try {
                await runCommand('npm install --package-lock-only', { log: false });
            } catch (error: any) {
                this.restoreFileSnapshot(packageJsonPath, originalPackageJson, true);
                this.restoreFileSnapshot(packageLockPath, originalPackageLock, packageLockExisted);
                throw error;
            }

            // 5. Verification
            if (this.hasTestScript()) {
                logger.engineer('Running verification (npm test)...');
                try {
                    await runCommand('npm test', { log: false });
                    logger.success('Verification passed!');
                } catch {
                    logger.error('Verification failed! Restoring modified files...');
                    this.restoreFileSnapshot(packageJsonPath, originalPackageJson, true);
                    this.restoreFileSnapshot(
                        packageLockPath,
                        originalPackageLock,
                        packageLockExisted
                    );
                    return false;
                }
            } else {
                logger.warn('No test script found in package.json. Skipping verification.');
            }

            // 6. Commit
            await this.git.stageFiles([
                'package.json',
                ...(fs.existsSync(packageLockPath) ? ['package-lock.json'] : []),
            ]);
            await this.git.commit(`fix(${packageName}): resolve ${vulnerabilityId}`);

            logger.success(`Fix committed on branch "${branchName}"`);
            return true;
        } catch (error: any) {
            logger.error('NpmFixer encountered an error:', error);
            return false;
        }
    }
}

export class PipFixer implements IFixer {
    readonly name = 'python';

    private git: GitManager;

    constructor() {
        this.git = new GitManager();
    }

    canFix(instruction: FixInstruction): boolean {
        if (instruction.ecosystem !== 'python') {
            return false;
        }

        const requirementsPath = path.resolve(
            process.cwd(),
            instruction.manifestPath || 'requirements.txt'
        );
        if (!fs.existsSync(requirementsPath)) {
            return false;
        }

        const content = fs.readFileSync(requirementsPath, 'utf-8');
        return content
            .split('\n')
            .some((line) => line.trim().startsWith(`${instruction.packageName}==`));
    }

    async applyFix(
        instruction: FixInstruction,
        vulnerabilityId: string,
        branchPrefix: string = DEFAULT_BRANCH_PREFIX
    ): Promise<boolean> {
        const requirementsPath = path.resolve(
            process.cwd(),
            instruction.manifestPath || 'requirements.txt'
        );
        let branchName = `${branchPrefix}-${instruction.packageName}`;
        const branchValidation = validator.validateBranchName(branchName);

        if (!branchValidation.valid) {
            branchName = validator.sanitizeBranchName(instruction.packageName, branchPrefix);
        }

        try {
            if (await this.git.hasUncommittedChanges()) {
                logger.error(
                    'Refusing to auto-fix with uncommitted changes present. Commit or stash changes first.'
                );
                return false;
            }

            await this.git.checkoutBranch(branchName);

            if (!fs.existsSync(requirementsPath)) {
                throw new Error('requirements.txt not found');
            }

            const originalContent = fs.readFileSync(requirementsPath, 'utf-8');
            const updatedContent = originalContent
                .split('\n')
                .map((line) => {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith(`${instruction.packageName}==`)) {
                        return line;
                    }

                    return `${instruction.packageName}==${instruction.targetVersion}`;
                })
                .join('\n');

            if (updatedContent === originalContent) {
                logger.error(`Package "${instruction.packageName}" not found in requirements.txt`);
                return false;
            }

            fs.writeFileSync(requirementsPath, updatedContent, 'utf-8');

            if (this.hasPytestSuite()) {
                try {
                    await runCommand('python3 -m pytest', { log: false });
                    logger.success('Python verification passed!');
                } catch {
                    logger.error('Python verification failed! Restoring modified files...');
                    fs.writeFileSync(requirementsPath, originalContent, 'utf-8');
                    return false;
                }
            } else {
                logger.warn('No pytest suite detected. Skipping Python verification.');
            }

            await this.git.stageFiles(['requirements.txt']);
            await this.git.commit(`fix(${instruction.packageName}): resolve ${vulnerabilityId}`);
            logger.success(`Fix committed on branch "${branchName}"`);
            return true;
        } catch (error: any) {
            logger.error('PipFixer encountered an error:', error);
            return false;
        }
    }

    private hasPytestSuite(): boolean {
        return (
            fs.existsSync(path.resolve(process.cwd(), 'pytest.ini')) ||
            fs.existsSync(path.resolve(process.cwd(), 'tests')) ||
            fs.existsSync(path.resolve(process.cwd(), 'tox.ini'))
        );
    }
}

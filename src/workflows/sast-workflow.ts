/**
 * SAST Workflow
 *
 * Encapsulates all Static Application Security Testing (SAST) orchestration
 * logic as a dedicated strategy class, implementing the IWorkflow contract.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runProcess } from '../services/process';
import { GIT_TIMEOUT_MS } from '../constants';

import { IWorkflow } from './index';
import { Diagnosis, ScanResult, Severity, WardenOptions, WardenRunResult } from '../types';
import { ScannerRegistry } from '../scanners';
import { SnykScanner } from '../agents/watchman/snyk';
import { NpmAuditScanner } from '../agents/watchman/npm-audit';
import { PipAuditScanner } from '../agents/watchman/pip-audit';
import { ProgressReporter } from '../utils/progress';
import { logger } from '../utils/logger';
import { getConfig } from '../utils/config';
import { DEFAULT_BRANCH_PREFIX, WORKSPACES_DIR } from '../constants';
import { selectVulnerabilitiesForFix } from '../utils/scan-results';
import { validator } from '../utils/validator';
import { buildRemediationPlan } from '../utils/advisor';
import { evaluatePolicy, writeApprovalRequest } from '../utils/policy';

type SastFixSummary = Pick<
    WardenRunResult,
    | 'selectedVulnerabilityIds'
    | 'attemptedFixes'
    | 'appliedFixes'
    | 'branches'
    | 'pullRequestUrls'
    | 'warnings'
>;

export class SastWorkflow implements IWorkflow {
    private progress: ProgressReporter;

    constructor() {
        const verbose = getConfig().get('logging').level === 'debug';
        this.progress = new ProgressReporter(verbose);
    }

    async run(options: WardenOptions): Promise<WardenRunResult> {
        const originalCwd = process.cwd();
        const result: WardenRunResult = {
            mode: 'sast',
            targetPath: options.targetPath,
            repository: options.repository,
            dryRun: options.dryRun,
            scanResult: undefined,
            selectedVulnerabilityIds: [],
            attemptedFixes: 0,
            appliedFixes: 0,
            branches: [],
            pullRequestUrls: [],
            advisoryPath: undefined,
            warnings: [],
        };

        try {
            if (options.repository) {
                const workspace = await this.prepareWorkspace(options.repository);
                process.chdir(workspace);
                result.targetPath = workspace;
                logger.info(`Working directory: ${process.cwd()}`);
            } else if (options.targetPath !== process.cwd()) {
                process.chdir(options.targetPath);
                logger.info(`Working directory: ${process.cwd()}`);
            }

            this.progress.addStep('scan', 'Security Scan');
            this.progress.startStep('scan', 'Running security scan...');

            const snykUtils = new SnykScanner();

            try {
                const scanResult = await this.runSecurityScan(options);
                result.scanResult = scanResult;
                this.progress.succeedStep('scan', 'Security scan completed');
                snykUtils.printSummary(scanResult as any);

                const fixSummary = await this.orchestrateFix(scanResult, options);
                Object.assign(result, fixSummary);

                logger.header('✅ Patrol Session Completed Successfully');
            } catch (scanError: any) {
                this.progress.failStep('scan', 'Security scan failed');
                logger.error('Scanner execution failed', scanError);

                throw scanError;
            }
        } finally {
            process.chdir(originalCwd);
        }

        return result;
    }

    private async prepareWorkspace(repoUrl: string): Promise<string> {
        this.progress.addStep('workspace', 'Prepare Workspace');
        this.progress.startStep('workspace', 'Preparing workspace...');

        try {
            const repoName = repoUrl.split('/').pop()?.replace('.git', '') || 'target-repo';
            const workspacePath = path.resolve(process.cwd(), WORKSPACES_DIR, repoName);

            if (fs.existsSync(workspacePath)) {
                this.progress.updateStep('workspace', `Updating ${repoName}...`);
                logger.debug(`Workspace for ${repoName} already exists. Pulling latest changes...`);
                await runProcess('git', ['pull', '--ff-only'], {
                    cwd: workspacePath,
                    timeout: GIT_TIMEOUT_MS,
                });
            } else {
                this.progress.updateStep('workspace', `Cloning ${repoName}...`);
                logger.debug(`Cloning ${repoUrl} into workspaces/${repoName}...`);
                fs.mkdirSync(path.dirname(workspacePath), { recursive: true });
                await runProcess('git', ['clone', '--', repoUrl, workspacePath], {
                    timeout: GIT_TIMEOUT_MS,
                });
            }

            this.progress.succeedStep('workspace', `Workspace ready: ${workspacePath}`);
            return workspacePath;
        } catch (error: any) {
            this.progress.failStep('workspace', 'Failed to prepare workspace');
            throw error;
        }
    }

    private async runSecurityScan(options: WardenOptions): Promise<ScanResult> {
        const config = getConfig().get('scanner');
        const timeoutMs = options.scanTimeoutMs ?? config.timeout;
        const registry = new ScannerRegistry();
        const available = {
            snyk: () => new SnykScanner({ timeoutMs, maxRetries: config.retries }).test(),
            'npm-audit': () => new NpmAuditScanner({ timeoutMs }).scan(),
            'pip-audit': () => new PipAuditScanner({ timeoutMs }).scan(),
        };
        const primary =
            options.scanner === 'npm-audit' || options.scanner === 'pip-audit'
                ? options.scanner
                : validator.detectProjectType(process.cwd()) === 'python'
                  ? 'pip-audit'
                  : 'snyk';
        registry.register({ name: primary, scan: available[primary] });
        if (
            config.fallback !== false &&
            (options.scanner === 'snyk' || options.scanner === 'all')
        ) {
            const fallback = primary === 'pip-audit' ? 'snyk' : 'npm-audit';
            registry.register({ name: fallback, scan: available[fallback] });
        }
        const scanned = await registry.scan(primary);
        return {
            ...scanned,
            scanner: scanned.scanner as ScanResult['scanner'],
            scanMode: 'sast',
            projectPath: process.cwd(),
            vulnerabilities: scanned.vulnerabilities.map((finding) => ({
                ...finding,
                fixedIn: finding.fixedIn || [],
                description: finding.description || '',
            })),
        };
    }

    private async orchestrateFix(
        scanResult: ScanResult,
        options: WardenOptions
    ): Promise<SastFixSummary> {
        const selected = selectVulnerabilitiesForFix(
            scanResult.vulnerabilities,
            options.minSeverity as Severity,
            options.maxFixes
        );

        if (selected.length === 0) {
            logger.success(
                `No vulnerabilities met the minimum severity threshold (${options.minSeverity}).`
            );
            return {
                selectedVulnerabilityIds: [],
                attemptedFixes: 0,
                appliedFixes: 0,
                branches: [],
                pullRequestUrls: [],
                warnings: [],
            };
        }

        logger.warn(
            `Selected ${selected.length} vulnerability(ies) at or above ${options.minSeverity} severity.`
        );

        const policyDecision = evaluatePolicy(
            scanResult,
            buildRemediationPlan(scanResult, {
                appliedFixes: 0,
                attemptedFixes: selected.length,
                warnings: [],
            }),
            options,
            getConfig().getConfig()
        );

        if (policyDecision.shouldBlockFixes) {
            const approvalRequest = writeApprovalRequest(
                scanResult,
                buildRemediationPlan(scanResult, {
                    appliedFixes: 0,
                    attemptedFixes: selected.length,
                    warnings: policyDecision.reasons,
                }),
                policyDecision
            );
            logger.warn(
                `Policy blocked automated fixes. Approval request written to ${approvalRequest}`
            );
            return {
                selectedVulnerabilityIds: selected.map((vulnerability) => vulnerability.id),
                attemptedFixes: selected.length,
                appliedFixes: 0,
                branches: [],
                pullRequestUrls: [],
                warnings: policyDecision.reasons,
            };
        }

        logger.section('🔧 ENGINEER AGENT | Diagnosing & Patching');

        const { EngineerAgent } = await import('../agents/engineer');
        const engineer = new EngineerAgent();
        const warnings: string[] = [];
        const branches: string[] = [];
        const pullRequestUrls: string[] = [];

        const diagnoses = await engineer.diagnose({ ...scanResult, vulnerabilities: selected });
        const diagnosisById = new Map<string, Diagnosis>(
            diagnoses.map((diagnosis: Diagnosis) => [
                JSON.stringify([
                    diagnosis.vulnerabilityId,
                    diagnosis.packageName || diagnosis.fixInstruction?.packageName || '',
                ]),
                diagnosis,
            ])
        );
        const actionableDiagnoses = selected
            .map(
                (vulnerability) =>
                    diagnosisById.get(
                        JSON.stringify([vulnerability.id, vulnerability.packageName])
                    ) || diagnosisById.get(JSON.stringify([vulnerability.id, '']))
            )
            .filter((diagnosis): diagnosis is Diagnosis => Boolean(diagnosis));

        if (actionableDiagnoses.length === 0) {
            logger.warn('No actionable diagnoses generated.');
            return {
                selectedVulnerabilityIds: selected.map((vulnerability) => vulnerability.id),
                attemptedFixes: 0,
                appliedFixes: 0,
                branches: [],
                pullRequestUrls: [],
                warnings: ['Selected vulnerabilities could not be mapped to actionable diagnoses.'],
            };
        }

        if (options.dryRun) {
            logger.info('DRY RUN MODE: Would apply the following fixes:');
            actionableDiagnoses.forEach((diagnosis, index) => {
                logger.info(`  ${index + 1}. Vulnerability: ${diagnosis.vulnerabilityId}`);
                logger.info(`     Description: ${diagnosis.description}`);
                logger.info(`     Fix:         ${diagnosis.suggestedFix}`);
                logger.info(`     Files:       ${diagnosis.filesToModify.join(', ') || 'None'}`);
            });

            return {
                selectedVulnerabilityIds: selected.map((vulnerability) => vulnerability.id),
                attemptedFixes: actionableDiagnoses.length,
                appliedFixes: 0,
                branches: [],
                pullRequestUrls: [],
                warnings: [],
            };
        }

        const diplomat = process.env.GITHUB_TOKEN
            ? new (await import('../agents/diplomat')).DiplomatAgent()
            : undefined;
        let appliedFixes = 0;

        for (const diagnosis of actionableDiagnoses) {
            const fixSuccess = await engineer.applyFix(diagnosis);
            if (!fixSuccess) {
                warnings.push(`Failed to apply fix for ${diagnosis.vulnerabilityId}.`);
                continue;
            }

            appliedFixes++;
            const branchName = diagnosis.fixInstruction
                ? validator.sanitizeBranchName(
                      diagnosis.fixInstruction.packageName,
                      DEFAULT_BRANCH_PREFIX
                  )
                : `${DEFAULT_BRANCH_PREFIX}-${diagnosis.vulnerabilityId.toLowerCase()}`;
            branches.push(branchName);

            if (!diplomat) {
                warnings.push(
                    `Skipped PR creation for ${diagnosis.vulnerabilityId}: GITHUB_TOKEN is not set.`
                );
                continue;
            }

            logger.section('🤝 DIPLOMAT AGENT | Opening Pull Request');
            const pushed = await diplomat.pushBranch(branchName);

            if (!pushed) {
                warnings.push(`Branch push failed for ${branchName}; PR was not created.`);
                continue;
            }

            try {
                const matched = selected.find(
                    (vulnerability) =>
                        vulnerability.id === diagnosis.vulnerabilityId &&
                        vulnerability.packageName ===
                            (diagnosis.packageName || diagnosis.fixInstruction?.packageName)
                );
                const prUrl = await diplomat.createPullRequest({
                    branch: branchName,
                    title: diplomat.generatePrTitle(branchName, diagnosis.vulnerabilityId),
                    body: diplomat.generatePrBody(
                        diagnosis.vulnerabilityId,
                        matched?.severity,
                        diagnosis.description
                    ),
                    severity: matched?.severity,
                });
                pullRequestUrls.push(prUrl);
                logger.success(`Pull Request created: ${prUrl}`);
            } catch (error: any) {
                warnings.push(`PR creation failed for ${branchName}: ${error.message}`);
            }
        }

        return {
            selectedVulnerabilityIds: selected.map((vulnerability) => vulnerability.id),
            attemptedFixes: actionableDiagnoses.length,
            appliedFixes,
            branches,
            pullRequestUrls,
            warnings,
        };
    }
}

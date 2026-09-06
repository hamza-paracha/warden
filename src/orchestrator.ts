import { writeJsonAtomic } from './services/artifacts';
import { writeSarifReport } from './utils/sarif';
import { validateRunOptions } from './utils/run-options';
/**
 * Warden Orchestrator
 *
 * The main entry point for the Warden security scanning and auto-patching
 * pipeline. All workflow logic is delegated to dedicated strategy classes so
 * this module stays thin and easy to extend:
 *
 *   SastWorkflow  — Static Application Security Testing
 *   DastWorkflow  — Dynamic Application Security Testing
 *
 * Adding a new scan mode only requires implementing IWorkflow and adding a
 * branch here.
 */

import * as path from 'path';
import { loadRules } from './core/rules';
import { loadSpecs } from './core/spec';
import { logger } from './utils/logger';
import { WardenOptions, WardenRunResult } from './types';
import { buildRemediationPlan, createHistoryEntry } from './utils/advisor';
import { RunHistoryService } from './utils/history';
import { writeAgentRunRecord, writeHtmlReport, writeMarkdownReport } from './utils/reports';
import { getConfig } from './utils/config';
import { NotificationService } from './utils/notifications';
import { evaluatePolicy, writeApprovalRequest } from './utils/policy';
import { MemoryService } from './utils/memory';

// Re-export WardenOptions so existing callers that imported it from
// orchestrator.ts continue to work without modification.
export type { WardenOptions };

/**
 * Run the full Warden security workflow.
 *
 * Selects the appropriate workflow strategy based on `options.scanMode`
 * (defaults to SAST), loads rules & specs, then delegates execution.
 *
 * @param options  Top-level configuration for this run.
 */
export async function runWarden(options: WardenOptions): Promise<WardenRunResult> {
    validateRunOptions(options);
    // ── 1. Load Core Configuration ────────────────────────────────────────────
    logger.section('📋 Loading Configuration');

    loadRules(); // Throws if WARDEN_CORE.md is missing

    const specs = loadSpecs();
    if (specs.length === 0) {
        logger.warn('No active specifications found in /SPEC. Continuing with default behaviour.');
    } else {
        logger.info(`Loaded ${specs.length} specification(s)`);
    }

    // ── 2. Select and execute the appropriate workflow ────────────────────────
    const workflowResult =
        options.scanMode === 'dast'
            ? await new (await import('./workflows/dast-workflow')).DastWorkflow().run(options)
            : await new (await import('./workflows/sast-workflow')).SastWorkflow().run(options);

    const originalCwd = process.cwd();
    try {
        process.chdir(workflowResult.targetPath);
        if (workflowResult.scanResult) {
            writeJsonAtomic(
                path.join('scan-results', 'scan-results.json'),
                workflowResult.scanResult
            );
            const remediationPlan = buildRemediationPlan(workflowResult.scanResult, workflowResult);
            workflowResult.remediationPlan = remediationPlan;

            const config = getConfig().getConfig();
            const policyDecision = evaluatePolicy(
                workflowResult.scanResult,
                remediationPlan,
                options,
                config
            );
            workflowResult.policyDecision = policyDecision;

            workflowResult.reportPaths = {
                sarif: writeSarifReport(workflowResult.scanResult),
                markdown: writeMarkdownReport(
                    workflowResult.scanResult,
                    workflowResult,
                    remediationPlan
                ),
                html: writeHtmlReport(workflowResult.scanResult),
                agentRunRecord: writeAgentRunRecord(
                    workflowResult.scanResult,
                    workflowResult,
                    remediationPlan,
                    policyDecision
                ),
            };

            if (policyDecision.approvalRequired && !policyDecision.approvalSatisfied) {
                workflowResult.reportPaths.approvalRequest = writeApprovalRequest(
                    workflowResult.scanResult,
                    remediationPlan,
                    policyDecision
                );
            }

            const historyService = new RunHistoryService();
            workflowResult.history = historyService.append(
                createHistoryEntry(workflowResult.scanResult, workflowResult)
            );

            const memoryService = new MemoryService();
            workflowResult.memory = memoryService.update(
                workflowResult.repository || workflowResult.targetPath,
                workflowResult.scanResult
            );

            const notificationService = new NotificationService(config.notifications);
            await notificationService.send({
                title: 'Warden Scan Completed',
                message: remediationPlan.summary,
                severity:
                    remediationPlan.posture === 'critical'
                        ? 'error'
                        : remediationPlan.posture === 'elevated'
                          ? 'warning'
                          : 'success',
                details: {
                    repository: workflowResult.repository || workflowResult.targetPath,
                    vulnerabilities: workflowResult.scanResult.summary.total,
                    fixed: workflowResult.appliedFixes,
                    prUrl: workflowResult.pullRequestUrls[0],
                },
            });
        }
    } finally {
        process.chdir(originalCwd);
    }

    return workflowResult;
}

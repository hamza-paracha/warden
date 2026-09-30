import {
    RemediationAction,
    RemediationPlan,
    RunHistoryEntry,
    ScanResult,
    Severity,
    WardenRunResult,
} from '../types';
import { SEVERITY_PRIORITY } from '../constants';

const FIXABLE_PRIORITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function buildRemediationPlan(
    scanResult: ScanResult,
    runResult: Pick<WardenRunResult, 'appliedFixes' | 'attemptedFixes' | 'warnings'>
): RemediationPlan {
    let autoFixableCount = 0;
    let manualCount = 0;
    let exploitCount = 0;
    let weightedRisk = 0;
    // Only six distinct manual packages are shown; do not retain every finding.
    const manualPackages = new Set<string>();
    for (const vulnerability of scanResult.vulnerabilities) {
        if (vulnerability.fixedIn.length > 0) {
            autoFixableCount++;
        } else {
            manualCount++;
            if (manualPackages.size < 6 && vulnerability.packageName) {
                manualPackages.add(vulnerability.packageName);
            }
        }
        if (vulnerability.exploitAvailable) exploitCount++;
        weightedRisk += findingRisk(vulnerability);
    }
    const riskScore = Math.min(100, weightedRisk);
    const posture = classifyPosture(riskScore);
    const immediateActions = buildImmediateActions(
        scanResult,
        autoFixableCount,
        runResult.appliedFixes,
        exploitCount
    );
    const manualFollowUps = [...manualPackages].map(
        (packageName) => `Investigate manual remediation path for ${packageName}`
    );
    const strategicImprovements = buildStrategicImprovements(
        scanResult,
        runResult.warnings,
        manualCount
    );

    return {
        riskScore,
        posture,
        autoFixableCount,
        manualCount,
        exploitCount,
        immediateActions,
        manualFollowUps,
        strategicImprovements,
        summary: buildSummary(scanResult, autoFixableCount, manualCount, exploitCount, posture),
    };
}

export function createHistoryEntry(
    scanResult: ScanResult,
    runResult: Pick<
        WardenRunResult,
        'mode' | 'targetPath' | 'repository' | 'appliedFixes' | 'attemptedFixes' | 'remediationPlan'
    >
): RunHistoryEntry {
    return {
        timestamp: scanResult.timestamp,
        mode: runResult.mode,
        targetPath: runResult.targetPath,
        repository: runResult.repository,
        totalVulnerabilities: scanResult.summary.total,
        critical: scanResult.summary.critical,
        high: scanResult.summary.high,
        medium: scanResult.summary.medium,
        low: scanResult.summary.low,
        appliedFixes: runResult.appliedFixes,
        attemptedFixes: runResult.attemptedFixes,
        autoFixableCount: runResult.remediationPlan?.autoFixableCount ?? 0,
        manualCount: runResult.remediationPlan?.manualCount ?? 0,
        riskScore: runResult.remediationPlan?.riskScore ?? calculateRiskScore(scanResult),
    };
}

/** Shared by plans, history, and baselines without building unused advice. */
export function calculateRiskScore(scanResult: ScanResult): number {
    let weightedRisk = 0;
    for (const vulnerability of scanResult.vulnerabilities) {
        weightedRisk += findingRisk(vulnerability);
    }
    return Math.min(100, weightedRisk);
}

function findingRisk(vulnerability: ScanResult['vulnerabilities'][number]): number {
    const base = SEVERITY_PRIORITY[vulnerability.severity] * 20;
    const cvssWeight = vulnerability.cvssScore ? Math.round(vulnerability.cvssScore * 3) : 0;
    const exploitWeight = vulnerability.exploitAvailable ? 25 : 0;
    return base + cvssWeight + exploitWeight;
}

function classifyPosture(riskScore: number): RemediationPlan['posture'] {
    if (riskScore >= 90) return 'critical';
    if (riskScore >= 60) return 'elevated';
    if (riskScore >= 30) return 'guarded';
    return 'stable';
}

function buildImmediateActions(
    scanResult: ScanResult,
    autoFixableCount: number,
    appliedFixes: number,
    exploitCount: number
): RemediationAction[] {
    const actions: RemediationAction[] = [];
    const highestSeverity = FIXABLE_PRIORITIES.find((severity) => scanResult.summary[severity] > 0);

    if (highestSeverity) {
        actions.push({
            title: `Contain ${highestSeverity} severity findings first`,
            priority: highestSeverity === 'critical' ? 'urgent' : 'high',
            rationale: `${scanResult.summary[highestSeverity]} ${highestSeverity} finding(s) remain in the current scan.`,
        });
    }

    if (autoFixableCount > appliedFixes) {
        actions.push({
            title: 'Increase automated remediation throughput',
            priority: 'high',
            rationale: `${autoFixableCount - appliedFixes} fixable issue(s) still require execution or batching.`,
        });
    }

    if (exploitCount > 0) {
        actions.push({
            title: 'Escalate exploit-backed findings to incident priority',
            priority: 'urgent',
            rationale:
                'At least one finding has a known exploit path and should bypass normal backlog flow.',
        });
    }

    return actions.slice(0, 4);
}

function buildStrategicImprovements(
    scanResult: ScanResult,
    warnings: string[],
    manualCount: number
): string[] {
    const improvements: string[] = [];

    if (scanResult.summary.high + scanResult.summary.critical > 0) {
        improvements.push('Add Warden to CI so high and critical findings fail fast before merge.');
    }

    if (manualCount > 0) {
        improvements.push(
            'Track transitive dependencies and vendor advisories so manual-only issues are not orphaned.'
        );
    }

    if (warnings.some((warning) => warning.includes('GITHUB_TOKEN'))) {
        improvements.push(
            'Configure GitHub credentials so Warden can complete the full branch-to-PR loop automatically.'
        );
    }

    if (warnings.some((warning) => warning.includes('uncommitted changes'))) {
        improvements.push(
            'Run Warden in a clean workspace or dedicated CI checkout to preserve deterministic remediation.'
        );
    }

    if (improvements.length === 0) {
        improvements.push(
            'Raise max automated fixes per run gradually and monitor regression signals.'
        );
    }

    return improvements;
}

function buildSummary(
    scanResult: ScanResult,
    autoFixableCount: number,
    manualCount: number,
    exploitCount: number,
    posture: RemediationPlan['posture']
): string {
    return [
        `${scanResult.summary.total} finding(s) detected with ${autoFixableCount} auto-fixable and ${manualCount} manual follow-up item(s).`,
        exploitCount > 0
            ? `${exploitCount} finding(s) have exploit context.`
            : 'No exploit-backed findings were detected.',
        `Current security posture is ${posture}.`,
    ].join(' ');
}

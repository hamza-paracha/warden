/**
 * Warden Shared Types
 *
 * Centralized type definitions used across the application.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ScannerType = 'snyk' | 'npm-audit' | 'pip-audit' | 'nmap' | 'metasploit' | 'mock';
export type ScanMode = 'sast' | 'dast';
export type Ecosystem = 'npm' | 'python';

export interface Vulnerability {
    id: string;
    title: string;
    severity: Severity;
    packageName: string;
    version: string;
    fixedIn: string[];
    description: string;
    cvssScore?: number;
    cwe?: string[];
    references?: string[];
    ecosystem?: Ecosystem;
    // DAST-specific fields
    targetHost?: string;
    targetPort?: number;
    service?: string;
    serviceVersion?: string;
    exploitAvailable?: boolean;
    exploitModule?: string;
    findings?: string[];
}

export interface ScanSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export interface ScanResult {
    timestamp: string;
    vulnerabilities: Vulnerability[];
    summary: ScanSummary;
    scanner?: ScannerType;
    projectPath?: string;
    scanMode?: ScanMode;
    metadata?: { scanDuration?: number; retryCount?: number; errors?: string[] };
    scanMetadata?: {
        target?: string;
        scanType?: string;
        duration?: number;
        nmapVersion?: string;
        msfVersion?: string;
        [key: string]: any;
    };
}

export interface FixResult {
    vulnerabilityId: string;
    packageName: string;
    success: boolean;
    previousVersion: string;
    newVersion: string;
    error?: string;
}

export interface PRResult {
    branch: string;
    url: string;
    number: number;
    title: string;
    labels: string[];
}

export interface WardenConfig {
    scanner: 'snyk' | 'npm-audit' | 'auto';
    autoFix: boolean;
    createPR: boolean;
    severityThreshold: Severity;
    ignoredVulnerabilities: string[];
    labelsForPR: string[];
    prAssignee?: string;
    slackWebhook?: string;
    outputFormat: 'text' | 'json';
    verbose: boolean;
    dryRun: boolean;
    dast?: DastConfig;
}

export interface WardenReport {
    timestamp: string;
    config: Partial<WardenConfig>;
    scan: ScanResult;
    fixes: FixResult[];
    pullRequests: PRResult[];
    duration: number;
    exitCode: number;
}

// CLI Option Types
export interface ScanOptions {
    target?: string;
    scanner?: 'snyk' | 'npm-audit';
    fix?: boolean;
    pr?: boolean;
    dryRun?: boolean;
    json?: boolean;
    quiet?: boolean;
    verbose?: boolean;
}

export interface ValidateOptions {
    verbose?: boolean;
}

// Agent Types

/**
 * Structured data for applying a package fix.
 * Replaces regex-parsed strings in the fix pipeline.
 */
export interface FixInstruction {
    ecosystem: Ecosystem;
    packageName: string;
    currentVersion: string;
    targetVersion: string;
    manifestPath?: string;
}

export interface Diagnosis {
    vulnerabilityId: string;
    packageName?: string;
    description: string;
    suggestedFix: string;
    filesToModify: string[];
    /** Structured fix data; present for SAST auto-fixable vulnerabilities */
    fixInstruction?: FixInstruction;
}

export interface PrConfig {
    branch: string;
    title: string;
    body: string;
    severity?: string;
    labels?: string[];
}

// DAST Configuration Types
export interface DastTarget {
    url: string;
    description?: string;
    authorized: boolean;
    ports?: string;
    excludePorts?: string;
}

export interface NmapConfig {
    enabled: boolean;
    scanType: 'quick' | 'standard' | 'comprehensive' | 'stealth';
    portRange?: string;
    timing?: number;
    options?: string[];
    outputFormat?: 'xml' | 'normal';
}

export interface MetasploitConfig {
    enabled: boolean;
    mode: 'scan-only' | 'safe-exploits' | 'full';
    modules?: string[];
    timeout?: number;
}

export interface SafetyConfig {
    requireConfirmation: boolean;
    authorizedTargetsOnly: boolean;
    disableExploits: boolean;
    maxScanDuration?: number;
}

export interface DastConfig {
    enabled: boolean;
    targets: DastTarget[];
    nmap: NmapConfig;
    metasploit: MetasploitConfig;
    safety: SafetyConfig;
}

/**
 * Top-level options passed to the runWarden orchestration function.
 */
export interface WardenOptions {
    targetPath: string;
    repository?: string;
    dryRun: boolean;
    scanner: 'snyk' | 'npm-audit' | 'pip-audit' | 'all';
    minSeverity: Severity;
    maxFixes: number;
    verbose: boolean;
    scanMode?: ScanMode;
    dastTarget?: string;
    ci?: boolean;
    approvalToken?: string;
    scanTimeoutMs?: number;
}

export interface WardenRunResult {
    mode: ScanMode;
    targetPath: string;
    repository?: string;
    dryRun: boolean;
    scanResult?: ScanResult;
    selectedVulnerabilityIds: string[];
    attemptedFixes: number;
    appliedFixes: number;
    branches: string[];
    pullRequestUrls: string[];
    advisoryPath?: string;
    reportPaths?: {
        markdown?: string;
        html?: string;
        approvalRequest?: string;
        agentRunRecord?: string;
        sarif?: string;
    };
    remediationPlan?: RemediationPlan;
    history?: RunHistorySnapshot;
    memory?: MemorySnapshot;
    policyDecision?: PolicyDecision;
    warnings: string[];
}

export interface RemediationAction {
    title: string;
    priority: 'urgent' | 'high' | 'medium' | 'low';
    rationale: string;
}

export interface RemediationPlan {
    riskScore: number;
    posture: 'critical' | 'elevated' | 'guarded' | 'stable';
    autoFixableCount: number;
    manualCount: number;
    exploitCount: number;
    immediateActions: RemediationAction[];
    manualFollowUps: string[];
    strategicImprovements: string[];
    summary: string;
}

export interface RunHistoryEntry {
    timestamp: string;
    mode: ScanMode;
    targetPath: string;
    repository?: string;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    appliedFixes: number;
    attemptedFixes: number;
    autoFixableCount: number;
    manualCount: number;
    riskScore: number;
}

export interface RunHistorySnapshot {
    latest: RunHistoryEntry;
    previous?: RunHistoryEntry;
    trend: 'improving' | 'worsening' | 'unchanged' | 'first-run';
}

export interface AgentRunRecord {
    generatedAt: string;
    mode: ScanMode;
    targetPath: string;
    repository?: string;
    scanTimestamp: string;
    scanSummary: ScanSummary;
    riskScore: number;
    posture: RemediationPlan['posture'];
    selectedVulnerabilityIds: string[];
    attemptedFixes: number;
    appliedFixes: number;
    branches: string[];
    pullRequestUrls: string[];
    advisoryPath?: string;
    policyDecision?: Pick<
        PolicyDecision,
        | 'shouldBlockFixes'
        | 'shouldFailPipeline'
        | 'approvalRequired'
        | 'approvalSatisfied'
        | 'reasons'
    >;
    warnings: string[];
    whyMatters: string[];
    topFindings: Array<{
        id: string;
        title: string;
        severity: Severity;
        packageName: string;
        version: string;
    }>;
}

export interface MemoryHotspot {
    packageName: string;
    occurrences: number;
    lastSeverity: Severity;
}

export interface MemorySnapshot {
    repoKey: string;
    runCount: number;
    topHotspots: MemoryHotspot[];
}

export interface PolicyDecision {
    shouldBlockFixes: boolean;
    shouldFailPipeline: boolean;
    exitCode: number;
    reasons: string[];
    approvalRequired: boolean;
    approvalSatisfied: boolean;
}

export interface BaselineFinding {
    fingerprint: string;
    id: string;
    title: string;
    severity: Severity;
    packageName: string;
    version: string;
    fixedIn: string[];
    ecosystem?: Ecosystem;
    targetHost?: string;
    targetPort?: number;
    service?: string;
}

export interface WardenBaseline {
    schemaVersion: 1;
    generatedAt: string;
    scanTimestamp: string;
    scanner?: ScannerType;
    scanMode?: ScanMode;
    projectPath?: string;
    summary: ScanSummary;
    riskScore: number;
    findings: BaselineFinding[];
}

export interface BaselineFindingDelta {
    fingerprint: string;
    baseline?: BaselineFinding;
    current?: BaselineFinding;
    severityChanged?: {
        from: Severity;
        to: Severity;
    };
}

export interface BaselineComparison {
    generatedAt: string;
    baselineRiskScore: number;
    currentRiskScore: number;
    riskScoreDelta: number;
    newFindings: BaselineFindingDelta[];
    resolvedFindings: BaselineFindingDelta[];
    worsenedFindings: BaselineFindingDelta[];
    unchangedCount: number;
    summary: {
        new: number;
        resolved: number;
        worsened: number;
        unchanged: number;
    };
}

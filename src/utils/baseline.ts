import * as fs from 'fs';
import * as path from 'path';
import {
    BaselineComparison,
    BaselineFinding,
    BaselineFindingDelta,
    ScanResult,
    Severity,
    Vulnerability,
    WardenBaseline,
} from '../types';
import { SCAN_RESULTS_PATH, SEVERITY_PRIORITY, WARDEN_BASELINE_FILE } from '../constants';
import { calculateRiskScore } from './advisor';
import { writeJsonAtomic } from '../services/artifacts';
import { isSeverityAtLeast } from './scan-results';

export function readScanResult(scanResultsPath: string = SCAN_RESULTS_PATH): ScanResult {
    const resolvedPath = path.resolve(scanResultsPath);

    if (!fs.existsSync(resolvedPath)) {
        throw new Error(`Scan results not found at ${resolvedPath}. Run "warden scan" first.`);
    }

    const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
    if (!isScanResult(parsed)) {
        throw new Error(`Invalid scan result file at ${resolvedPath}.`);
    }

    return parsed;
}

export function readBaseline(baselinePath: string = WARDEN_BASELINE_FILE): WardenBaseline {
    const resolvedPath = path.resolve(baselinePath);

    if (!fs.existsSync(resolvedPath)) {
        throw new Error(
            `Baseline not found at ${resolvedPath}. Create one with "warden baseline --create".`
        );
    }

    const parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf-8'));
    if (!isWardenBaseline(parsed)) {
        throw new Error(`Invalid Warden baseline file at ${resolvedPath}.`);
    }

    return parsed;
}

export function writeBaseline(
    scanResult: ScanResult,
    baselinePath: string = WARDEN_BASELINE_FILE
): WardenBaseline {
    const resolvedPath = path.resolve(baselinePath);
    const baseline = createBaselineSnapshot(scanResult);
    writeJsonAtomic(resolvedPath, baseline);
    return baseline;
}

export function createBaselineSnapshot(scanResult: ScanResult): WardenBaseline {
    return {
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        scanTimestamp: scanResult.timestamp,
        scanner: scanResult.scanner,
        scanMode: scanResult.scanMode,
        projectPath: scanResult.projectPath,
        summary: scanResult.summary,
        riskScore: calculateRiskScore(scanResult),
        findings: scanResult.vulnerabilities
            .map(vulnerabilityToBaselineFinding)
            .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
    };
}

export function compareBaseline(
    currentScan: ScanResult,
    baseline: WardenBaseline
): BaselineComparison {
    const currentFindings = currentScan.vulnerabilities.map(vulnerabilityToBaselineFinding);
    const currentByFingerprint = toFindingMap(currentFindings);
    const baselineByFingerprint = toFindingMap(baseline.findings);

    const newFindings: BaselineFindingDelta[] = [];
    const resolvedFindings: BaselineFindingDelta[] = [];
    const worsenedFindings: BaselineFindingDelta[] = [];
    let unchangedCount = 0;

    for (const current of currentFindings) {
        const previous = baselineByFingerprint.get(current.fingerprint);

        if (!previous) {
            newFindings.push({
                fingerprint: current.fingerprint,
                current,
            });
            continue;
        }

        if (SEVERITY_PRIORITY[current.severity] > SEVERITY_PRIORITY[previous.severity]) {
            worsenedFindings.push({
                fingerprint: current.fingerprint,
                baseline: previous,
                current,
                severityChanged: {
                    from: previous.severity,
                    to: current.severity,
                },
            });
            continue;
        }

        unchangedCount++;
    }

    for (const previous of baseline.findings) {
        if (!currentByFingerprint.has(previous.fingerprint)) {
            resolvedFindings.push({
                fingerprint: previous.fingerprint,
                baseline: previous,
            });
        }
    }

    const currentRiskScore = calculateRiskScore(currentScan);

    return {
        generatedAt: new Date().toISOString(),
        baselineRiskScore: baseline.riskScore,
        currentRiskScore,
        riskScoreDelta: currentRiskScore - baseline.riskScore,
        newFindings: sortDeltas(newFindings),
        resolvedFindings: sortDeltas(resolvedFindings),
        worsenedFindings: sortDeltas(worsenedFindings),
        unchangedCount,
        summary: {
            new: newFindings.length,
            resolved: resolvedFindings.length,
            worsened: worsenedFindings.length,
            unchanged: unchangedCount,
        },
    };
}

export function hasBaselineRegression(
    comparison: BaselineComparison,
    minimumSeverity: Severity
): boolean {
    const newRegression = comparison.newFindings.some((delta) =>
        delta.current ? isSeverityAtLeast(delta.current.severity, minimumSeverity) : false
    );

    const worsenedRegression = comparison.worsenedFindings.some((delta) =>
        delta.current ? isSeverityAtLeast(delta.current.severity, minimumSeverity) : false
    );

    return newRegression || worsenedRegression;
}

export function describeFinding(finding: BaselineFinding): string {
    const subject = finding.packageName || finding.service || finding.targetHost || 'unknown';
    return `${finding.severity.toUpperCase()} ${finding.id} ${subject}@${finding.version || 'unknown'} - ${finding.title}`;
}

function vulnerabilityToBaselineFinding(vulnerability: Vulnerability): BaselineFinding {
    return {
        fingerprint: fingerprintVulnerability(vulnerability),
        id: vulnerability.id,
        title: vulnerability.title,
        severity: vulnerability.severity,
        packageName: vulnerability.packageName,
        version: vulnerability.version,
        fixedIn: vulnerability.fixedIn,
        ecosystem: vulnerability.ecosystem,
        targetHost: vulnerability.targetHost,
        targetPort: vulnerability.targetPort,
        service: vulnerability.service,
    };
}

function fingerprintVulnerability(vulnerability: Vulnerability): string {
    const subject =
        vulnerability.packageName ||
        [vulnerability.targetHost, vulnerability.targetPort, vulnerability.service]
            .filter((value) => value !== undefined && value !== '')
            .join(':') ||
        'unknown';
    const ecosystem = vulnerability.ecosystem || 'generic';

    return [
        ecosystem,
        normalizeFingerprintPart(subject),
        normalizeFingerprintPart(vulnerability.id),
    ].join('|');
}

function normalizeFingerprintPart(value: string | number): string {
    return String(value).trim().toLowerCase().replace(/\s+/g, '-');
}

function toFindingMap(findings: BaselineFinding[]): Map<string, BaselineFinding> {
    return new Map(findings.map((finding) => [finding.fingerprint, finding]));
}

function sortDeltas(deltas: BaselineFindingDelta[]): BaselineFindingDelta[] {
    return [...deltas].sort((left, right) => {
        const leftSeverity = left.current?.severity || left.baseline?.severity || 'low';
        const rightSeverity = right.current?.severity || right.baseline?.severity || 'low';
        const severityDelta = SEVERITY_PRIORITY[rightSeverity] - SEVERITY_PRIORITY[leftSeverity];

        if (severityDelta !== 0) {
            return severityDelta;
        }

        return left.fingerprint.localeCompare(right.fingerprint);
    });
}

function isScanResult(value: unknown): value is ScanResult {
    return Boolean(
        value &&
        typeof value === 'object' &&
        Array.isArray((value as ScanResult).vulnerabilities) &&
        (value as ScanResult).summary &&
        typeof (value as ScanResult).timestamp === 'string'
    );
}

function isWardenBaseline(value: unknown): value is WardenBaseline {
    return Boolean(
        value &&
        typeof value === 'object' &&
        (value as WardenBaseline).schemaVersion === 1 &&
        Array.isArray((value as WardenBaseline).findings) &&
        (value as WardenBaseline).summary &&
        typeof (value as WardenBaseline).riskScore === 'number'
    );
}

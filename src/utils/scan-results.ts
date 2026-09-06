import { Severity, Vulnerability, ScanSummary } from '../types';
import { SEVERITY_PRIORITY } from '../constants';

export function isSeverityAtLeast(severity: Severity, minimumSeverity: Severity): boolean {
    return SEVERITY_PRIORITY[severity] >= SEVERITY_PRIORITY[minimumSeverity];
}

export function selectVulnerabilitiesForFix(
    vulnerabilities: Vulnerability[],
    minimumSeverity: Severity,
    maxFixes: number
): Vulnerability[] {
    if (!Number.isSafeInteger(maxFixes) || maxFixes < 0) {
        throw new Error('maxFixes must be a non-negative safe integer');
    }
    if (maxFixes === 0) return [];

    // A bounded heap keeps only the best K findings: O(n log K) time, O(K) memory.
    // The original index breaks ties, preserving the previous stable-sort behavior.
    type Candidate = { vulnerability: Vulnerability; index: number };
    const compare = (a: Candidate, b: Candidate): number =>
        SEVERITY_PRIORITY[a.vulnerability.severity] - SEVERITY_PRIORITY[b.vulnerability.severity] ||
        (a.vulnerability.cvssScore ?? 0) - (b.vulnerability.cvssScore ?? 0) ||
        b.index - a.index;
    const heap: Candidate[] = [];
    for (let index = 0; index < vulnerabilities.length; index++) {
        const vulnerability = vulnerabilities[index];
        if (!isSeverityAtLeast(vulnerability.severity, minimumSeverity)) continue;
        const candidate = { vulnerability, index };
        if (heap.length < maxFixes) {
            heap.push(candidate);
            let child = heap.length - 1;
            while (child > 0) {
                const parent = (child - 1) >>> 1;
                if (compare(heap[parent], heap[child]) <= 0) break;
                [heap[parent], heap[child]] = [heap[child], heap[parent]];
                child = parent;
            }
        } else if (compare(candidate, heap[0]) > 0) {
            heap[0] = candidate;
            let parent = 0;
            while (parent * 2 + 1 < heap.length) {
                let child = parent * 2 + 1;
                if (child + 1 < heap.length && compare(heap[child + 1], heap[child]) < 0) child++;
                if (compare(heap[parent], heap[child]) <= 0) break;
                [heap[parent], heap[child]] = [heap[child], heap[parent]];
                parent = child;
            }
        }
    }
    return heap.sort((a, b) => compare(b, a)).map(({ vulnerability }) => vulnerability);
}

export function summarizeVulnerabilities(
    vulnerabilities: readonly { severity: Severity }[]
): ScanSummary {
    const summary: ScanSummary = {
        total: vulnerabilities.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
    for (const vulnerability of vulnerabilities) summary[vulnerability.severity]++;
    return summary;
}

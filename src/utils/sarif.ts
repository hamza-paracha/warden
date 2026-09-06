import * as path from 'path';
import { createHash } from 'crypto';
import { ScanResult, Severity } from '../types';
import { writeJsonAtomic } from '../services/artifacts';

const levels: Record<Severity, 'error' | 'warning' | 'note'> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
};

/** SARIF 2.1.0 export. Dependency locations deliberately omit invented line numbers. */
export function buildSarif(scan: ScanResult) {
    const ruleIndexes = new Map<string, number>();
    const rules: Array<{
        id: string;
        shortDescription: { text: string };
        fullDescription: { text: string };
    }> = [];
    const results = scan.vulnerabilities.map((finding) => {
        let ruleIndex = ruleIndexes.get(finding.id);
        if (ruleIndex === undefined) {
            ruleIndex = rules.length;
            ruleIndexes.set(finding.id, ruleIndex);
            rules.push({
                id: finding.id,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.description || finding.title },
            });
        }
        const identity = JSON.stringify([
            finding.id,
            finding.ecosystem || 'npm',
            finding.packageName,
            finding.targetHost || '',
            finding.targetPort ?? '',
            finding.service || '',
        ]);
        return {
            ruleId: finding.id,
            ruleIndex,
            level: levels[finding.severity],
            message: {
                text: `${finding.title} in ${finding.packageName}@${finding.version}. ${
                    finding.fixedIn?.length
                        ? `Fixed in: ${finding.fixedIn.join(', ')}.`
                        : 'No known fixed version.'
                }`,
            },
            partialFingerprints: {
                'wardenFinding/v1': createHash('sha256').update(identity).digest('hex'),
            },
            ...(scan.scanMode === 'dast' || finding.targetHost
                ? {}
                : {
                      locations: [
                          {
                              physicalLocation: {
                                  artifactLocation: {
                                      uri:
                                          finding.ecosystem === 'python'
                                              ? 'requirements.txt'
                                              : 'package.json',
                                  },
                              },
                          },
                      ],
                  }),
            properties: {
                severity: finding.severity,
                packageName: finding.packageName,
                installedVersion: finding.version,
                fixedIn: finding.fixedIn || [],
            },
        };
    });
    return {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: { driver: { name: 'Warden', rules } },
                automationDetails: { id: `warden/${scan.scanner || 'scan'}/` },
                results,
            },
        ],
    };
}

export function writeSarifReport(
    scan: ScanResult,
    outputPath = path.resolve('scan-results', 'warden.sarif')
): string {
    writeJsonAtomic(outputPath, buildSarif(scan));
    return outputPath;
}

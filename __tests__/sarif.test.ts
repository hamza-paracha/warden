import { buildSarif } from '../src/utils/sarif';
import { ScanResult } from '../src/types';
import fixture from './fixtures/sast-scan-result.json';
const scan = fixture as ScanResult;

it('exports severity levels and manifest locations without inventing line numbers', () => {
    const sarif = buildSarif(scan);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[0].locations).toEqual([
        { physicalLocation: { artifactLocation: { uri: 'package.json' } } },
    ]);
});
it('deduplicates rules while retaining separate package findings', () => {
    const first = scan.vulnerabilities[0];
    const sarif = buildSarif({
        ...scan,
        vulnerabilities: [first, { ...first, packageName: 'other' }],
    });
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results.map((result) => result.ruleIndex)).toEqual([0, 0]);
    expect(sarif.runs[0].results[0].partialFingerprints).not.toEqual(
        sarif.runs[0].results[1].partialFingerprints
    );
});
it('keeps fingerprints stable when versions and severity change', () => {
    const changed = {
        ...scan,
        vulnerabilities: scan.vulnerabilities.map((v) => ({
            ...v,
            version: '9.0.0',
            severity: 'low' as const,
        })),
    };
    expect(buildSarif(changed).runs[0].results.map((v) => v.partialFingerprints)).toEqual(
        buildSarif(scan).runs[0].results.map((v) => v.partialFingerprints)
    );
});
it('exports Python locations and does not invent manifests for infrastructure findings', () => {
    const python = {
        ...scan,
        vulnerabilities: [{ ...scan.vulnerabilities[0], ecosystem: 'python' as const }],
    };
    expect(
        buildSarif(python).runs[0].results[0].locations?.[0].physicalLocation.artifactLocation.uri
    ).toBe('requirements.txt');
    expect(buildSarif({ ...scan, scanMode: 'dast' }).runs[0].results[0].locations).toBeUndefined();
});
it('exports a clean scan with empty rule and result lists', () => {
    const result = buildSarif({ ...scan, vulnerabilities: [] });
    expect(result.runs[0].results).toEqual([]);
    expect(result.runs[0].tool.driver.rules).toEqual([]);
});

#!/usr/bin/env node
// CPU-only benchmark. Optionally compare against a saved compiled advisor.js.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { performance } = require('node:perf_hooks');
const { buildRemediationPlan } = require('../dist/utils/advisor');
const { summarizeVulnerabilities } = require('../dist/utils/scan-results');
const vulnerabilities = Array.from({ length: 100000 }, (_, index) => ({
    id: String(index), title: 'Benchmark finding', packageName: `pkg-${index}`,
    version: '1.0.0', description: '', fixedIn: index % 3 ? [] : ['1.0.1'],
    severity: ['low', 'medium', 'high', 'critical'][index % 4],
    cvssScore: (index % 101) / 10, exploitAvailable: index % 10 === 0,
}));
const scan = { timestamp: '2026-01-01T00:00:00Z', vulnerabilities,
    summary: summarizeVulnerabilities(vulnerabilities) };
const run = { appliedFixes: 1, attemptedFixes: 2, warnings: ['GITHUB_TOKEN is not set'] };
function median(fn) {
    for (let i = 0; i < 5; i++) fn();
    const times = Array.from({ length: 25 }, () => {
        const start = performance.now(); fn(); return performance.now() - start;
    });
    return times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
}
const result = { findings: vulnerabilities.length };
if (process.argv[2]) {
    const filename = path.resolve(__dirname, '../dist/utils/advisor.js');
    const reference = new Module(filename, module);
    reference.filename = filename;
    reference.paths = module.paths;
    reference._compile(fs.readFileSync(process.argv[2], 'utf8'), filename);
    const before = () => reference.exports.buildRemediationPlan(scan, run);
    assert.deepEqual(buildRemediationPlan(scan, run), before());
    result.beforeMs = +median(before).toFixed(3);
}
result.afterMs = +median(() => buildRemediationPlan(scan, run)).toFixed(3);
if (result.beforeMs) result.speedup = +(result.beforeMs / result.afterMs).toFixed(2);
console.log(JSON.stringify(result));

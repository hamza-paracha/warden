#!/usr/bin/env node
// Deterministic CPU benchmark; this does not measure scanner/network latency.
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { selectVulnerabilitiesForFix } = require('../dist/utils/scan-results');
const ranks = { low: 1, medium: 2, high: 3, critical: 4 };
const severities = Object.keys(ranks);
let seed = 42;
const input = Array.from({ length: 100000 }, (_, i) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return { id: String(i), title: 'Benchmark finding', packageName: `pkg-${i}`, version: '1.0.0',
        description: '', fixedIn: [], severity: severities[(seed >>> 16) % 4], cvssScore: seed % 101 / 10 };
});
const reference = (limit) => [...input].filter(v => ranks[v.severity] >= ranks.high)
    .sort((a, b) => ranks[b.severity] - ranks[a.severity] || b.cvssScore - a.cvssScore).slice(0, limit);
function median(fn) {
    for (let i = 0; i < 5; i++) fn();
    const times = Array.from({ length: 15 }, () => { const start = performance.now(); fn(); return performance.now() - start; });
    return times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
}
for (const limit of [1, 10, 100]) {
    assert.deepEqual(selectVulnerabilitiesForFix(input, 'high', limit), reference(limit));
    const before = median(() => reference(limit));
    const after = median(() => selectVulnerabilitiesForFix(input, 'high', limit));
    console.log(JSON.stringify({ findings: input.length, maxFixes: limit, fullSortMs: +before.toFixed(3), topKMs: +after.toFixed(3), speedup: +(before / after).toFixed(2) }));
}

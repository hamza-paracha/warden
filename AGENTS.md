# Warden agent notes

- Node >= 22.12. Build: `npm run build`. Tests: `npm test` (CI: `npm run test:ci`, coverage gates in `jest.config.js`).
- Format: `npm run format` / `npm run format:check` (Prettier, 4-space, CI-enforced).
- Packaged smoke test: `npm run smoke` (run after `npm run build`).
- Quickstart release gate: `npm run smoke:quickstart` (needs network) installs the packed tarball into a clean prefix and runs every `warden ...` command shown in `website/index.html` and `README.md` verbatim. Each advertised command needs an entry in its `expectations` table. While `package.json`'s version is not on npm, both files must say "source-only".
- Supply-chain code lives in `src/supply-chain/` (registry, tarball, signals, lockfile, policy), agent integration in `src/guard/` and `src/mcp/`, signing in `src/attestation/`. Docs: `docs/SUPPLY-CHAIN.md`.
- Tests use the in-memory fake registry in `__tests__/helpers/npm-fixtures.ts`; unit tests never hit the network.
- The MCP server must never write to stdout except protocol messages (the logger uses console.log, which `startMcpServer` redirects).

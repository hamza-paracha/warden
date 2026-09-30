# Warden website

Static source for https://warden.hamzaparacha.me. No package install or build is required.

Serve this directory with a local static server to preview it. The release popup uses a native dialog and remembers dismissal under `warden:release:1.9.0:dismissed` in localStorage. The navigation's “What's new” button reopens it. Escape, ×, “Got it”, and the backdrop dismiss it. If storage is unavailable, dismissal works for the current page visit.

For the next release, update the popup copy, release link, and `data-version` value in `index.html`; the dismissal key is derived from it.

The existing Vercel `warden` project uses `website` as its root directory for GitHub deployments. Push website changes to `main` to deploy, or run the Vercel CLI from the repository root with that project linked. `website/vercel.json` explicitly skips installation and builds. Do not change the project's root to the CLI application.

The install button copies the displayed command, announces success to screen readers,
and selects the command with a helpful message if clipboard access is unavailable.
Feature animations use CSS and respect reduced-motion preferences; the content
remains visible without JavaScript. No observer or animation library is required.

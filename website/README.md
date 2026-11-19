# Warden website

Static source for https://warden.hamzaparacha.me. No package install or build is required.

Serve this directory with any static server to preview it, for example
`python3 -m http.server` from `website/`.

The "What's new" dialog opens once per visitor and remembers dismissal in
localStorage under `warden:release:<data-version>:dismissed`, using the
`data-version` value on `#release-modal` in `index.html`. Change that value to show
the dialog again after a new release. Escape, ×, "Got it", and the backdrop close it.

The install button copies the displayed command, announces success to screen
readers, and selects the command if clipboard access is unavailable. Animations are
CSS-only and turn off for visitors who prefer reduced motion; all content stays
visible without JavaScript.

The Vercel `warden` project uses `website` as its root directory. Pushing to `main`
deploys it. `website/vercel.json` skips installation and builds. Do not change the
project's root to the CLI application.

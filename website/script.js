document.addEventListener('DOMContentLoaded', () => {
    const releaseModal = document.getElementById('release-modal');
    const releaseTrigger = document.getElementById('release-trigger');
    const dismissalKey = `warden:release:${releaseModal?.dataset.version}:dismissed`;

    if (releaseModal && releaseTrigger && typeof releaseModal.showModal === 'function') {
        releaseTrigger.hidden = false;
        releaseTrigger.addEventListener('click', () => releaseModal.showModal());
        document.getElementById('release-close').addEventListener('click', () => releaseModal.close());
        document.getElementById('release-dismiss').addEventListener('click', () => releaseModal.close());
        // The native dialog handles focus trapping, focus restoration, and Escape.
        releaseModal.addEventListener('close', () => {
            try { localStorage.setItem(dismissalKey, 'true'); } catch { /* Storage can be unavailable. */ }
        });
        releaseModal.addEventListener('click', (event) => {
            if (event.target !== releaseModal) return;
            const bounds = releaseModal.getBoundingClientRect();
            if (event.clientX < bounds.left || event.clientX > bounds.right ||
                event.clientY < bounds.top || event.clientY > bounds.bottom) releaseModal.close();
        });
        let dismissed = false;
        try { dismissed = localStorage.getItem(dismissalKey) === 'true'; } catch { /* Show without persistence. */ }
        if (!dismissed) releaseModal.showModal();
    }

    const copyBtn = document.getElementById('copy-btn');
    const command = document.getElementById('install-command');
    const copyStatus = document.getElementById('copy-status');
    if (!copyBtn || !command || !copyStatus) return;

    let resetTimer;
    copyBtn.addEventListener('click', async () => {
        clearTimeout(resetTimer);
        copyBtn.disabled = true;
        copyStatus.textContent = '';
        try {
            await navigator.clipboard.writeText(command.textContent.trim());
            copyBtn.classList.add('is-copied');
            copyBtn.setAttribute('aria-label', 'Copied install command');
            copyStatus.textContent = 'Install command copied.';
        } catch {
            // Keep the command easy to copy when clipboard permissions are denied.
            const selection = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(command);
            selection?.removeAllRanges();
            selection?.addRange(range);
            copyBtn.classList.remove('is-copied');
            copyBtn.setAttribute('aria-label', 'Copy install command');
            copyStatus.textContent = 'Copy unavailable. Select and copy the command above.';
        } finally {
            copyBtn.disabled = false;
            resetTimer = setTimeout(() => {
                copyBtn.classList.remove('is-copied');
                copyBtn.setAttribute('aria-label', 'Copy install command');
                copyStatus.textContent = '';
            }, 4000);
        }
    });
});

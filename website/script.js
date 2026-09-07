document.addEventListener('DOMContentLoaded', () => {
    const releaseModal = document.getElementById('release-modal');
    const releaseTrigger = document.getElementById('release-trigger');
    const dismissalKey = 'warden:release:1.9.0:dismissed';

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

    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const command = 'npm install -g @devdonzo/warden';
            navigator.clipboard.writeText(command).then(() => {
                const originalContent = copyBtn.innerHTML;

                // Success Tab Checkmark
                copyBtn.innerHTML = `
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                `;

                setTimeout(() => {
                    copyBtn.innerHTML = originalContent;
                }, 2000);
            });
        });
    }

    // Scroll reveal for features
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });

    document.querySelectorAll('.feature-item').forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateY(10px)';
        item.style.transition = `all 0.5s ease-out ${index * 0.1}s`;
        observer.observe(item);
    });
});

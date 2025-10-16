    </div>

        <div class="modal fade" id="pkceModal" tabindex="-1" aria-labelledby="pkceModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="pkceModalLabel">Technical Details (PKCE)</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <?php if ($pkce): ?>
                        <div class="mb-3">
                            <small class="text-muted">Code Verifier:</small>
                            <code class="d-block p-2 bg-light border rounded small text-break"><?= htmlspecialchars($pkce['code_verifier']) ?></code>
                        </div>
                        <div class="mb-3">
                            <small class="text-muted">Code Challenge:</small>
                            <code class="d-block p-2 bg-light border rounded small text-break"><?= htmlspecialchars($pkce['code_challenge']) ?></code>
                        </div>
                        <div>
                            <small class="text-muted">State:</small>
                            <code class="d-block p-2 bg-light border rounded small text-break"><?= htmlspecialchars($pkce['state']) ?></code>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        <?php if (isset($_SESSION['access_token']) && $timeRemaining !== null): ?>

        let remainingTime = parseInt(document.getElementById('timeRemaining').dataset.initialRemaining, 10);
        const timeEl = document.getElementById('timeRemaining');

        function updateCountdownDisplay() {
            if (timeEl && remainingTime !== null) {
                timeEl.textContent = remainingTime + ' sec';

                timeEl.classList.remove('text-warning-bold', 'text-danger-bold');
                if (remainingTime <= 30 && remainingTime > 10) {
                    timeEl.classList.add('text-warning-bold');
                } else if (remainingTime <= 10) {
                    timeEl.classList.add('text-danger-bold');
                }
            }
        }

        let countdownInterval = setInterval(() => {
            if (remainingTime > 0) {
                remainingTime--;
                updateCountdownDisplay();
            } else if (remainingTime === 0) {
                remainingTime = null;
                updateCountdownDisplay();
            }
        }, 1000);

        let checkInterval = setInterval(async () => {
            try {
                const formData = new FormData();
                formData.append('action', 'check_token_status');

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    body: formData
                });

                const data = await response.json();

                if (data.session_expired) {
                    clearInterval(checkInterval);
                    clearInterval(countdownInterval);
                    location.reload();
                    return;
                }

                if (data.success && data.valid && data.remaining !== null) {
                    remainingTime = data.remaining;
                    updateCountdownDisplay();

                    if (data.auto_refreshed) {
                        clearInterval(checkInterval);
                        clearInterval(countdownInterval);
                        location.reload();
                    }
                }
            } catch (e) {
                console.error('Error checking status:', e);
            }
        }, 30000);

        updateCountdownDisplay();

        <?php endif; ?>
    </script>
</body>
</html>

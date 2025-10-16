<?php

$timeRemaining = isset($_SESSION['token_timestamp'], $_SESSION['expires_in'])
    ? max(0, $_SESSION['expires_in'] - (time() - $_SESSION['token_timestamp']))
    : null;

$statusBadge = '<span class="badge bg-success">✓ Valid</span>';
?>

<div class="alert alert-light border">
    <div class="d-flex justify-content-between align-items-center">
        <div>
            <strong>Token Status:</strong> <?= $statusBadge ?>
            <?php if ($timeRemaining !== null): ?>
                | <strong>Remaining:</strong> <span id="timeRemaining" data-initial-remaining="<?= $timeRemaining ?>"><?= $timeRemaining ?> sec</span>
            <?php endif; ?>
        </div>
    </div>
</div>

<div class="card mb-4">
    <div class="card-body">
        <h6 class="text-muted mb-2">Access Token</h6>
        <code class="d-block p-2 bg-light border rounded small text-break"><?= htmlspecialchars($_SESSION['access_token']) ?></code>
    </div>
</div>

<?php if (!empty($_SESSION['refresh_token'])): ?>
    <div class="card mb-4">
        <div class="card-body">
            <h6 class="text-muted mb-2">Refresh Token</h6>
            <code class="d-block p-2 bg-light border rounded small text-break"><?= htmlspecialchars($_SESSION['refresh_token']) ?></code>
        </div>
    </div>
<?php endif; ?>

<?php if ($userData !== null): ?>
    <div class="card mb-4">
        <div class="card-header bg-success text-white">
            <strong>Retrieved Data</strong>
        </div>
        <div class="card-body">
            <pre class="mb-0 small"><?= htmlspecialchars(json_encode($userData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?></pre>
        </div>
    </div>
<?php endif; ?>

<div class="row g-3">
    <?php if (!empty($_SESSION['refresh_token'])): ?>
        <div class="col-md-6">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">🔄 Refresh Token</h5>
                    <p class="card-text text-muted small">Get a new Access Token via Refresh Token</p>
                    <form method="POST">
                        <input type="hidden" name="action" value="refresh_token">
                        <button type="submit" class="btn btn-primary w-100">Refresh</button>
                    </form>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <div class="col-md-6">
        <div class="card h-100">
            <div class="card-body">
                <h5 class="card-title">👤 User Data</h5>
                <p class="card-text text-muted small">Retrieve profile information from the server</p>
                <form method="POST">
                    <input type="hidden" name="action" value="fetch_user_data">
                    <button type="submit" class="btn btn-success w-100">Get Data</button>
                </form>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card h-100">
            <div class="card-body">
                <h5 class="card-title">🔍 Token Introspection</h5>
                <p class="card-text text-muted small">Check token status and metadata</p>
                <button type="button" class="btn btn-info w-100" data-bs-toggle="collapse" data-bs-target="#introspectForm">Open Form</button>
                <div class="collapse mt-3" id="introspectForm">
                    <form method="POST">
                        <input type="hidden" name="action" value="introspect_token">
                        <div class="mb-2">
                            <input type="text" name="token_to_introspect" value="<?= htmlspecialchars($_SESSION['access_token']) ?>" class="form-control form-control-sm" placeholder="Token">
                        </div>
                        <div class="mb-2">
                            <select name="token_type_hint" class="form-select form-select-sm">
                                <option value="access_token">Access Token</option>
                                <option value="refresh_token">Refresh Token</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-info btn-sm w-100">Introspect</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card h-100">
            <div class="card-body">
                <h5 class="card-title">🚫 Revoke Token</h5>
                <p class="card-text text-muted small">Annul token on the server</p>
                <button type="button" class="btn btn-warning w-100" data-bs-toggle="collapse" data-bs-target="#revokeForm">Open Form</button>
                <div class="collapse mt-3" id="revokeForm">
                    <form method="POST">
                        <input type="hidden" name="action" value="revoke_token">
                        <div class="mb-2">
                            <input type="text" name="token_to_revoke" value="<?= htmlspecialchars($_SESSION['access_token']) ?>" class="form-control form-control-sm" placeholder="Token">
                        </div>
                        <div class="mb-2">
                            <select name="token_type_hint" class="form-select form-select-sm">
                                <option value="access_token">Access Token</option>
                                <option value="refresh_token">Refresh Token</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-warning btn-sm w-100">Revoke</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="text-center mt-4">
    <form method="POST" class="d-inline">
        <input type="hidden" name="action" value="logout">
        <button type="submit" class="btn btn-outline-secondary">🚪 Logout</button>
    </form>
</div>

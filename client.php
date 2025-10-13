<?php

session_start();

// --- CLIENT CONFIGURATION ---
const XAUTHCONNECT_BASE_URL = 'http://127.0.0.1:8010';
const CLIENT_ID = 'test_client_123';
const CLIENT_SECRET = 'test_secret_key';
const REDIRECT_URI = 'http://127.0.0.1:8081/client.php';
// --- END OF CONFIGURATION ---

function generateRandomString(int $length = 128): string {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[random_int(0, $charactersLength - 1)];
    }
    return $randomString;
}

function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function makeApiRequest(string $endpoint, array $postData = [], ?string $bearerToken = null): array {
    $ch = curl_init($endpoint);

    if (!empty($postData)) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $headers = ['Content-Type: application/x-www-form-urlencoded'];
    if ($bearerToken) {
        $headers[] = 'Authorization: Bearer ' . $bearerToken;
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    return [
        'success' => $httpCode >= 200 && $httpCode < 300,
        'code' => $httpCode,
        'data' => json_decode($response, true) ?? [],
        'raw' => $response,
        'error' => $curlError
    ];
}

function refreshAccessToken(): ?array {
    if (empty($_SESSION['refresh_token'])) {
        return null;
    }

    $result = makeApiRequest(
        XAUTHCONNECT_BASE_URL . '/xauth/token/refresh',
        [
            'client_id' => CLIENT_ID,
            'client_secret' => CLIENT_SECRET,
            'refresh_token' => $_SESSION['refresh_token']
        ]
    );

    if ($result['success'] && isset($result['data']['access_token'])) {
        $_SESSION['access_token'] = $result['data']['access_token'];
        $_SESSION['refresh_token'] = $result['data']['refresh_token'] ?? $_SESSION['refresh_token'];
        $_SESSION['expires_in'] = $result['data']['expires_in'] ?? null;
        $_SESSION['token_timestamp'] = time();
        return $result['data'];
    }

    return null;
}

function validateTokenOnServer(): array {
    if (!isset($_SESSION['access_token'])) {
        return ['valid' => false, 'error' => 'No token'];
    }

    $result = makeApiRequest(
        XAUTHCONNECT_BASE_URL . '/xauth/introspect',
        [
            'client_id' => CLIENT_ID,
            'client_secret' => CLIENT_SECRET,
            'token' => $_SESSION['access_token'],
            'token_type_hint' => 'access_token'
        ]
    );

    if ($result['success'] && isset($result['data']['active'])) {
        return [
            'valid' => $result['data']['active'] === true,
            'data' => $result['data']
        ];
    }

    return ['valid' => false, 'error' => 'Validation failed', 'http_code' => $result['code']];
}

function isTokenExpired(): bool {
    if (!isset($_SESSION['token_timestamp']) || !isset($_SESSION['expires_in'])) {
        return false;
    }

    $elapsed = time() - $_SESSION['token_timestamp'];
    // Consider token expired 30 seconds before actual expiration time
    return $elapsed >= ($_SESSION['expires_in'] - 30);
}

function generateNewPKCE(): array {
    $codeVerifier = generateRandomString(128);
    $codeChallenge = base64url_encode(hash('sha256', $codeVerifier, true));
    $state = bin2hex(random_bytes(16));

    $_SESSION['pkce_code_verifier'] = $codeVerifier;
    $_SESSION['oauth_state'] = $state;

    return [
        'code_verifier' => $codeVerifier,
        'code_challenge' => $codeChallenge,
        'state' => $state
    ];
}

$output = '';
$error = '';
$success = '';
$userData = null;
$timeRemaining = null;

// --- CALLBACK HANDLING ---
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    $state = $_GET['state'] ?? null;

    if (!isset($_SESSION['pkce_code_verifier']) || !isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $state) {
        $error = 'Security error: invalid state or code_verifier.';
    } else {
        $result = makeApiRequest(
            XAUTHCONNECT_BASE_URL . '/xauth/token',
            [
                'grant_type' => 'authorization_code',
                'client_id' => CLIENT_ID,
                'client_secret' => CLIENT_SECRET,
                'code' => $code,
                'code_verifier' => $_SESSION['pkce_code_verifier'],
                'redirect_uri' => REDIRECT_URI
            ]
        );

        if ($result['success'] && isset($result['data']['access_token'])) {
            $_SESSION['access_token'] = $result['data']['access_token'];
            $_SESSION['refresh_token'] = $result['data']['refresh_token'] ?? null;
            $_SESSION['expires_in'] = $result['data']['expires_in'] ?? null;
            $_SESSION['token_timestamp'] = time();

            unset($_SESSION['pkce_code_verifier'], $_SESSION['oauth_state']);
            header('Location: ' . REDIRECT_URI);
            exit();
        } else {
            $error = "Failed to get token (HTTP {$result['code']}): " . ($result['raw'] ?? 'Unknown error');
        }
    }
}

// --- AJAX REQUEST HANDLING ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
    header('Content-Type: application/json');

    $action = $_POST['action'] ?? '';
    $response = ['success' => false, 'message' => '', 'data' => null];

    switch ($action) {
        case 'check_token_status':
            if (isset($_SESSION['access_token'])) {
                $serverValidation = validateTokenOnServer();

                $remainingSeconds = isset($_SESSION['token_timestamp'], $_SESSION['expires_in'])
                    ? max(0, $_SESSION['expires_in'] - (time() - $_SESSION['token_timestamp']))
                    : null;

                if (!$serverValidation['valid']) {
                    $newToken = refreshAccessToken();
                    if ($newToken) {
                        $serverValidation = validateTokenOnServer();

                        $remainingSeconds = isset($_SESSION['token_timestamp'], $_SESSION['expires_in'])
                            ? max(0, $_SESSION['expires_in'] - (time() - $_SESSION['token_timestamp']))
                            : null;

                        $response = [
                            'success' => true,
                            'valid' => $serverValidation['valid'],
                            'auto_refreshed' => true,
                            'remaining' => $remainingSeconds
                        ];
                    } else {
                        // DO NOT call session_destroy() here - only clear tokens
                        unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['expires_in'], $_SESSION['token_timestamp']);
                        $response = [
                            'success' => false,
                            'session_expired' => true,
                            'message' => 'Session expired'
                        ];
                    }
                } else {
                    $response = [
                        'success' => true,
                        'valid' => true,
                        'auto_refreshed' => false,
                        'remaining' => $remainingSeconds
                    ];
                }
            } else {
                $response = ['success' => false, 'session_expired' => true];
            }
            break;
    }

    echo json_encode($response);
    exit();
}

// --- REGULAR POST REQUEST HANDLING ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SESSION['access_token'])) {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'refresh_token':
            $newToken = refreshAccessToken();
            if ($newToken) {
                $success = 'Token successfully refreshed!';
            } else {
                $error = 'Failed to refresh token. The refresh token may have expired.';
            }
            break;

        case 'introspect_token':
            $result = makeApiRequest(
                XAUTHCONNECT_BASE_URL . '/xauth/introspect',
                [
                    'client_id' => CLIENT_ID,
                    'client_secret' => CLIENT_SECRET,
                    'token' => $_POST['token_to_introspect'] ?? $_SESSION['access_token'],
                    'token_type_hint' => $_POST['token_type_hint'] ?? 'access_token'
                ]
            );

            if ($result['success']) {
                $userData = $result['data'];
                $success = 'Introspection result received';
            } else {
                $error = "Introspection error (HTTP {$result['code']})";
            }
            break;

        case 'revoke_token':
            $result = makeApiRequest(
                XAUTHCONNECT_BASE_URL . '/xauth/revoke',
                [
                    'client_id' => CLIENT_ID,
                    'client_secret' => CLIENT_SECRET,
                    'token' => $_POST['token_to_revoke'] ?? $_SESSION['access_token'],
                    'token_type_hint' => $_POST['token_type_hint'] ?? 'access_token'
                ]
            );

            if ($result['success']) {
                $success = 'Token successfully revoked!';
                if (($_POST['token_to_revoke'] ?? $_SESSION['access_token']) === $_SESSION['access_token']) {
                    session_destroy();
                    header('Location: ' . REDIRECT_URI);
                    exit();
                }
            } else {
                $error = "Revocation error (HTTP {$result['code']})";
            }
            break;

        case 'fetch_user_data':
            $serverValidation = validateTokenOnServer();

            if (!$serverValidation['valid']) {
                $newToken = refreshAccessToken();
                if ($newToken) {
                    $serverValidation = validateTokenOnServer();
                } else {
                    // DO NOT call session_destroy() - only clear tokens
                    unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['expires_in'], $_SESSION['token_timestamp']);
                    $error = 'Session expired. Please log in again.';
                    break;
                }
            }

            if ($serverValidation['valid']) {
                $result = makeApiRequest(
                    XAUTHCONNECT_BASE_URL . '/xauth/user',
                    [],
                    $_SESSION['access_token']
                );

                if ($result['success']) {
                    $userData = $result['data'];
                    $success = 'User data successfully retrieved';
                } else {
                    $error = "Data retrieval error (HTTP {$result['code']}): " . $result['raw'];
                }
            } else {
                $error = 'Token invalid and could not be refreshed';
            }
            break;

        case 'logout':
            session_destroy();
            header('Location: ' . REDIRECT_URI);
            exit();
            break;
    }
}

// --- INTERFACE GENERATION ---
if (isset($_SESSION['access_token'])) {
    $serverValidation = validateTokenOnServer();

    if (!$serverValidation['valid']) {
        $newToken = refreshAccessToken();

        if (!$newToken) {
            // DO NOT call session_destroy() - only clear tokens, but preserve PKCE
            unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['expires_in'], $_SESSION['token_timestamp']);
            $error = 'Your session has expired (token invalid on server) and cannot be restored. Please log in again.';

            // Generate NEW PKCE parameters
            $pkce = generateNewPKCE();

            $authUrl = XAUTHCONNECT_BASE_URL . '/xauth/authorize?' . http_build_query([
                'client_id' => CLIENT_ID,
                'redirect_uri' => REDIRECT_URI,
                'scope' => 'profile:nickname profile:uuid',
                'code_challenge' => $pkce['code_challenge'],
                'code_challenge_method' => 'S256',
                'state' => $pkce['state']
            ]);

            $output = '<div class="text-center py-5">
                <h3 class="mb-3">Session Expired</h3>
                <p class="mb-4">Token is no longer valid on the server</p>
                <a href="' . htmlspecialchars($authUrl) . '" class="btn btn-primary">Log in again</a>
            </div>';
        } else {
            $serverValidation = validateTokenOnServer();
            $success = 'Token was automatically refreshed (the previous one was invalid).';
        }
    }

    if ($serverValidation['valid']) {
        $timeRemaining = isset($_SESSION['token_timestamp'], $_SESSION['expires_in'])
            ? max(0, $_SESSION['expires_in'] - (time() - $_SESSION['token_timestamp']))
            : null;

        $statusBadge = '<span class="badge bg-success">✓ Valid</span>';

        $output .= '<div class="alert alert-light border">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <strong>Token Status:</strong> ' . $statusBadge;
                    if ($timeRemaining !== null) {
                        $output .= ' | <strong>Remaining:</strong> <span id="timeRemaining" data-initial-remaining="' . $timeRemaining . '">' . $timeRemaining . ' sec</span>';
                    }
                $output .= '</div>
            </div>
        </div>';

        $output .= '<div class="card mb-4">
            <div class="card-body">
                <h6 class="text-muted mb-2">Access Token</h6>
                <code class="d-block p-2 bg-light border rounded small text-break">' . htmlspecialchars($_SESSION['access_token']) . '</code>
            </div>
        </div>';

        if (!empty($_SESSION['refresh_token'])) {
            $output .= '<div class="card mb-4">
                <div class="card-body">
                    <h6 class="text-muted mb-2">Refresh Token</h6>
                    <code class="d-block p-2 bg-light border rounded small text-break">' . htmlspecialchars($_SESSION['refresh_token']) . '</code>
                </div>
            </div>';
        }

        if ($userData !== null) {
            $output .= '<div class="card mb-4">
                <div class="card-header bg-success text-white">
                    <strong>Retrieved Data</strong>
                </div>
                <div class="card-body">
                    <pre class="mb-0 small">' . htmlspecialchars(json_encode($userData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</pre>
                </div>
            </div>';
        }

        $output .= '<div class="row g-3">';

        if (!empty($_SESSION['refresh_token'])) {
            $output .= '<div class="col-md-6">
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
            </div>';
        }

        $output .= '<div class="col-md-6">
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
        </div>';

        $output .= '<div class="col-md-6">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">🔍 Token Introspection</h5>
                    <p class="card-text text-muted small">Check token status and metadata</p>
                    <button type="button" class="btn btn-info w-100" data-bs-toggle="collapse" data-bs-target="#introspectForm">Open Form</button>
                    <div class="collapse mt-3" id="introspectForm">
                        <form method="POST">
                            <input type="hidden" name="action" value="introspect_token">
                            <div class="mb-2">
                                <input type="text" name="token_to_introspect" value="' . htmlspecialchars($_SESSION['access_token']) . '" class="form-control form-control-sm" placeholder="Token">
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
        </div>';

        $output .= '<div class="col-md-6">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">🚫 Revoke Token</h5>
                    <p class="card-text text-muted small">Annul token on the server</p>
                    <button type="button" class="btn btn-warning w-100" data-bs-toggle="collapse" data-bs-target="#revokeForm">Open Form</button>
                    <div class="collapse mt-3" id="revokeForm">
                        <form method="POST">
                            <input type="hidden" name="action" value="revoke_token">
                            <div class="mb-2">
                                <input type="text" name="token_to_revoke" value="' . htmlspecialchars($_SESSION['access_token']) . '" class="form-control form-control-sm" placeholder="Token">
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
        </div>';

        $output .= '</div>';

        $output .= '<div class="text-center mt-4">
            <form method="POST" class="d-inline">
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="btn btn-outline-secondary">🚪 Logout</button>
            </form>
        </div>';
    }

} else {
    $pkce = generateNewPKCE();

    $authUrl = XAUTHCONNECT_BASE_URL . '/xauth/authorize?' . http_build_query([
        'client_id' => CLIENT_ID,
        'redirect_uri' => REDIRECT_URI,
        'scope' => 'profile:nickname profile:uuid',
        'code_challenge' => $pkce['code_challenge'],
        'code_challenge_method' => 'S256',
        'state' => $pkce['state']
    ]);

    $output = '<div class="text-center py-5">
        <h2 class="mb-4">Welcome!</h2>
        <p class="lead mb-4">Click the button to authorize via XAuthConnect</p>
        <a href="' . htmlspecialchars($authUrl) . '" class="btn btn-primary btn-lg">Authorize</a>
    </div>

    <details class="mt-4">
        <summary class="text-muted" style="cursor: pointer;">Technical Details (PKCE)</summary>
        <div class="mt-3">
            <div class="mb-3">
                <small class="text-muted">Code Verifier:</small>
                <code class="d-block p-2 bg-light border rounded small text-break">' . htmlspecialchars($pkce['code_verifier']) . '</code>
            </div>
            <div class="mb-3">
                <small class="text-muted">Code Challenge:</small>
                <code class="d-block p-2 bg-light border rounded small text-break">' . htmlspecialchars($pkce['code_challenge']) . '</code>
            </div>
            <div>
                <small class="text-muted">State:</small>
                <code class="d-block p-2 bg-light border rounded small text-break">' . htmlspecialchars($pkce['state']) . '</code>
            </div>
        </div>
    </details>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XAuthConnect Demo Client</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            font-size: 28px;
            font-weight: 600;
        }
        .badge {
            font-weight: 500;
        }
        code {
            color: #333;
        }
        .text-warning-bold {
            font-weight: bold;
            color: #ffc107;
        }
        .text-danger-bold {
            font-weight: bold;
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 XAuthConnect Demo Client</h1>

        <?php if ($error): ?>
            <div class="alert alert-danger">
                <strong>Error:</strong> <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success:</strong> <?= htmlspecialchars($success) ?>
            </div>
        <?php endif; ?>

        <?= $output ?>
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

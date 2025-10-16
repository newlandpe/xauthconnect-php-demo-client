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

include 'templates/header.php';

$pkce = null;
if (!isset($_SESSION['access_token'])) {
    $pkce = generateNewPKCE();
}

if (isset($_SESSION['access_token'])) {
    $serverValidation = validateTokenOnServer();

    if (!$serverValidation['valid']) {
        $newToken = refreshAccessToken();

        if (!$newToken) {
            // DO NOT call session_destroy() - only clear tokens, but preserve PKCE
            unset($_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['expires_in'], $_SESSION['token_timestamp']);
            $error = 'Your session has expired (token invalid on server) and cannot be restored. Please log in again.';

            include 'templates/expired_session.php';
        } else {
            $serverValidation = validateTokenOnServer();
            $success = 'Token was automatically refreshed (the previous one was invalid).';
        }
    }

    if ($serverValidation['valid']) {
        include 'templates/dashboard.php';
    }
} else {
    include 'templates/login.php';
}

include 'templates/footer.php';
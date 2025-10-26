<?php
declare(strict_types=1);

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require 'vendor/autoload.php';
session_start();

use ChernegaSergiy\XAuthConnect\OAuth2\Client\Provider\XAuthConnect as XAuthConnectProvider;
use League\OAuth2\Client\Token\AccessToken;

// --- Initialize provider ---
try {
    $provider = new XAuthConnectProvider([
        'clientId'     => 'test_client_123',
        'clientSecret' => 'test_secret_key',
        'redirectUri'  => 'http://127.0.0.1:8083/client.php',
        'issuer'       => 'https://connect.fyennyi.pp.ua',
    ]);
} catch (\RuntimeException $e) {
    $pageTitle = 'Error';
    $error = 'Failed to connect to XAuthConnect: ' . $e->getMessage();
    include 'templates/header.php';
    include 'templates/footer.php';
    exit;
}

// --- Retrieve messages from previous redirects ---
$error = $_SESSION['error'] ?? null;
$success = $_SESSION['success'] ?? null;
unset($_SESSION['error'], $_SESSION['success']);

// --- Validate existing access token ---
if (isset($_SESSION['token'])) {
    /** @var AccessToken $token */
    $token = $_SESSION['token'];

    try {
        $introspection = $provider->introspectToken($token->getToken());

        // If token is inactive, clear session and force re-login
        if (empty($introspection['active'])) {
            unset($_SESSION['token']);
            header('Location: /client.php');
            exit;
        }
    } catch (\Exception $e) {
        // Token introspection failed or token expired
        unset($_SESSION['token']);
        $_SESSION['error'] = 'Session expired or invalid: ' . $e->getMessage();
        header('Location: /client.php');
        exit;
    }
}

// --- Handle OAuth2 callback ---
if (isset($_GET['code'])) {
    // Check state to prevent CSRF
    if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['oauth2state'] ?? null)) {
        unset($_SESSION['oauth2state']);
        $error = 'Invalid state parameter.';
    } else {
        try {
            // Exchange authorization code for an access token
            $token = $provider->getAccessToken('authorization_code', [
                'code'          => $_GET['code'],
                'code_verifier' => $_SESSION['pkce_code'] ?? '',
            ]);

            $_SESSION['token'] = $token;
            $_SESSION['id_token_claims'] = $token->getValues()['id_token_claims'] ?? [];

            // Redirect to main page to clean URL
            header('Location: /client.php');
            exit;
        } catch (\Exception $e) {
            $error = 'Failed to obtain access token: ' . $e->getMessage();
        }
    }
}

// --- Handle user actions (logout, revoke, etc.) ---
if (isset($_GET['action'])) {
    $action = $_GET['action'];

    if ($action === 'logout') {
        // Clear all session data and redirect
        session_destroy();
        header('Location: /client.php');
        exit;
    }

    if (!isset($_SESSION['token'])) {
        $error = 'No active session.';
    } else {
        $token = $_SESSION['token'];

        try {
            switch ($action) {
                case 'introspect':
                    // Check if the token is still active
                    $tokenToInspect = $_GET['token'] ?? $token->getToken();
                    $result = $provider->introspectToken($tokenToInspect);

                    if (!empty($result['active'])) {
                        $_SESSION['introspectionResult'] = $result;
                        $success = 'Token is active.';
                    } else {
                        unset($_SESSION['token']);
                        header('Location: /client.php');
                        exit;
                    }
                    break;

                case 'revoke':
                    // Revoke token and destroy session
                    $provider->revokeToken($token->getToken());
                    session_destroy();
                    header('Location: /client.php');
                    exit;

                case 'user_data':
                    // Fetch user info from resource endpoint
                    $_SESSION['userData'] = $provider->getResourceOwner($token)->toArray();
                    $success = 'User data retrieved successfully.';
                    break;

                case 'refresh_token':
                    // Refresh access token using refresh token
                    if (!$token->getRefreshToken()) {
                        $error = 'No refresh token available.';
                        break;
                    }

                    $newToken = $provider->getAccessToken('refresh_token', [
                        'refresh_token' => $token->getRefreshToken(),
                    ]);

                    $_SESSION['token'] = $newToken;
                    if (isset($newToken->getValues()['id_token_claims'])) {
                        $_SESSION['id_token_claims'] = $newToken->getValues()['id_token_claims'];
                    }
                    $success = 'Access token refreshed successfully!';
                    break;

                default:
                    $error = 'Unknown action.';
                    break;
            }
        } catch (\Exception $e) {
            $error = 'Action failed: ' . $e->getMessage();
        }
    }
}

// --- Render page ---
$pageTitle = 'XAuthConnect Demo Client';
include 'templates/header.php';

if (!isset($_SESSION['token'])) {
    // User not logged in — generate login URL
    $nonce = bin2hex(random_bytes(16));
    $_SESSION['oauth2nonce'] = $nonce;

    $authUrl = $provider->getAuthorizationUrl([
        'scope' => 'openid profile:nickname',
        'nonce' => $nonce,
    ]);

    $_SESSION['oauth2state'] = $provider->getState();
    $_SESSION['pkce_code'] = $provider->getPkceCode();

    include 'templates/login.php';
} else {
    // User logged in — show dashboard
    $claims = $_SESSION['id_token_claims'] ?? [];
    include 'templates/dashboard.php';
}

include 'templates/footer.php';


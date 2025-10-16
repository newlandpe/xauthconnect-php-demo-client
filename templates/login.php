<?php

$authUrl = XAUTHCONNECT_BASE_URL . '/xauth/authorize?' . http_build_query([
    'client_id' => CLIENT_ID,
    'redirect_uri' => REDIRECT_URI,
    'scope' => 'profile:nickname profile:uuid',
    'code_challenge' => $pkce['code_challenge'],
    'code_challenge_method' => 'S256',
    'state' => $pkce['state']
]);
?>

<div class="text-center py-5">
    <h2 class="mb-4">Welcome!</h2>
    <p class="lead mb-4">Click the button to authorize via XAuthConnect</p>
    <a href="<?= htmlspecialchars($authUrl) ?>" class="btn btn-primary btn-lg">Authorize</a>
</div>

<div class="text-center">
    <button type="button" class="btn btn-link text-muted" data-bs-toggle="modal" data-bs-target="#pkceModal">
        Technical Details (PKCE)
    </button>
</div>
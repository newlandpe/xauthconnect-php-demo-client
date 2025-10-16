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
    <h3 class="mb-3">Session Expired</h3>
    <p class="mb-4">Token is no longer valid on the server</p>
    <a href="<?= htmlspecialchars($authUrl) ?>" class="btn btn-primary">Log in again</a>
</div>

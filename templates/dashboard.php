<h2 class="ui header">Dashboard</h2>
<p class="lead">Welcome, <strong><?php echo (isset($claims['sub'])) ? htmlspecialchars($claims['sub']) : 'User'; ?></strong>!</p>
<p>You have successfully logged in and the client library has automatically validated your ID token.</p>

<?php if (isset($_SESSION['introspectionResult'])): ?>
    <h3 class="ui header">Introspection Result</h3>
    <pre><?php print_r($_SESSION['introspectionResult']); ?></pre>
    <?php unset($_SESSION['introspectionResult']); ?>
<?php endif; ?>

<?php if (!empty($claims['iss'])): ?>
    <h3 class="ui header">Validated ID Token Claims</h3>
    <pre><?php print_r($claims); ?></pre>
<?php endif; ?>

<?php if (isset($_SESSION['userData'])): ?>
    <h3 class="ui header">User Data</h3>
    <pre><?php print_r($_SESSION['userData']); ?></pre>
    <?php unset($_SESSION['userData']); ?>
<?php endif; ?>

<h3>Access Token</h3>
<p style="word-wrap: break-word;"><?= $token->getToken() ?></p>
<?php if ($token->getExpires()): ?>
    <p>Expires: <?= date('Y-m-d H:i:s', $token->getExpires()) ?> (<?= $token->getExpires() - time() ?> seconds remaining)</p>
<?php endif; ?>

<?php if ($token->getRefreshToken()): ?>
    <h3 class="ui header">Refresh Token</h3>
    <p style="word-wrap: break-word;"><?= $token->getRefreshToken() ?></p>
<?php endif; ?>

<div class="ui divider"></div>

<div class="ui segment">
    <h4 class="ui header">Introspect Token</h4>
    <div class="ui form">
        <div class="field">
            <label>Token to Introspect (optional)</label>
            <input type="text" id="tokenToIntrospect" placeholder="Paste a token here to introspect a specific one...">
        </div>
        <button class="ui info button" id="introspectButton">Introspect Token</button>
    </div>
</div>

<div class="ui divider"></div>

<div class="ui buttons">
    <a class="ui primary button" href="?action=user_data">Fetch User Data</a>
    <a class="ui positive button" href="?action=refresh_token">Refresh Token</a>
    <a class="ui warning button" href="?action=revoke">Revoke Token</a>
    <a class="ui negative button" href="?action=logout">Logout</a>
</div>

<script>
    document.getElementById('introspectButton').addEventListener('click', function() {
        var token = document.getElementById('tokenToIntrospect').value;
        var url = '?action=introspect';
        if (token) {
            url += '&token=' + encodeURIComponent(token);
        }
        window.location.href = url;
    });
</script>
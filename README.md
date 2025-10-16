# XAuthConnect PHP Demo Client

This is a demonstration of the [oauth2-xauthconnect](https://github.com/newlandpe/oauth2-xauthconnect) library, which is a generic OAuth 2.0 client implementation for PHP. This demo was created before the library was created.

A demonstration OAuth 2.0 client implementation showcasing integration with XAuthConnect authorization server using PHP.

![Demo Interface](screenshots/demo-interface.png)

## Features

- **OAuth 2.0 Authorization Code Flow** with PKCE (Proof Key for Code Exchange)
- **Token Management**: Access token, refresh token with automatic refresh
- **Real-time Token Status**: Live countdown timer showing token expiration
- **Complete Token Operations**:
  - Token refresh
  - Token introspection
  - Token revocation
  - User data retrieval
- **Session Management**: Automatic token validation and recovery
- **User-Friendly Interface**: Bootstrap 5-based responsive design

## Requirements

- PHP 7.4 or higher
- PHP extensions: `curl`, `json`, `session`
- XAuthConnect server running (default: `http://127.0.0.1:8010`)
- [Composer](https://getcomposer.org/)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/newlandpe/xauthconnect-php-demo-client.git
cd xauthconnect-php-demo-client
```

2. Install the dependencies using Composer:
```bash
composer require newlandpe/oauth2-xauthconnect
```

3. Configure the client by editing `client.php`:
```php
const XAUTHCONNECT_BASE_URL = 'http://127.0.0.1:8010';
const CLIENT_ID = 'test_client_123';
const CLIENT_SECRET = 'test_secret_key';
const REDIRECT_URI = 'http://127.0.0.1:8081/client.php';
```

4. Start a PHP development server:
```bash
php -S 127.0.0.1:8081
```

5. Open your browser and navigate to:
```
http://127.0.0.1:8081/client.php
```

## Configuration

### Client Credentials

Make sure your client is registered on the XAuthConnect server with matching credentials:

- **Client ID**: Must match `CLIENT_ID` constant
- **Client Secret**: Must match `CLIENT_SECRET` constant
- **Redirect URI**: Must be whitelisted on the authorization server

### Server URL

Update `XAUTHCONNECT_BASE_URL` to point to your XAuthConnect server instance.

## Usage

### Initial Authorization

1. Click the "Authorize" button
2. Log in on the XAuthConnect server
3. You'll be redirected back with an access token

### Token Operations

Once authorized, you can:

- **Refresh Token**: Get a new access token using the refresh token
- **Fetch User Data**: Retrieve user profile information
- **Introspect Token**: Check token status and metadata
- **Revoke Token**: Invalidate a token on the server
- **Logout**: End the session and clear all tokens

### Automatic Token Management

The client automatically:
- Monitors token expiration with a visual countdown
- Validates token status every 30 seconds
- Attempts to refresh expired tokens
- Handles session recovery gracefully

## Security Features

- **PKCE Implementation**: Protects against authorization code interception
- **State Parameter**: Prevents CSRF attacks
- **Secure Token Storage**: Session-based token management
- **Automatic Token Validation**: Server-side token verification

## File Structure

```
.
├── client.php         # Main application file
└── README.md          # This file
```

## API Endpoints Used

The client interacts with the following XAuthConnect endpoints:

- `GET /xauth/authorize` - OAuth authorization
- `POST /xauth/token` - Token exchange
- `POST /xauth/token/refresh` - Token refresh
- `POST /xauth/introspect` - Token introspection
- `POST /xauth/revoke` - Token revocation
- `GET /xauth/user` - User information

## Troubleshooting

### "Invalid state or code_verifier" Error

- Ensure PKCE parameters are correctly stored in the session
- Check that the redirect URI exactly matches the registered URI
- Verify that cookies are enabled in your browser

### Token Refresh Failures

- Check that the refresh token hasn't expired
- Verify client credentials are correct
- Ensure the XAuthConnect server is running

### Connection Issues

- Verify the `XAUTHCONNECT_BASE_URL` is correct
- Check that the authorization server is accessible
- Review PHP error logs for cURL errors

## Development

### Testing Different Scenarios

You can test various OAuth flows:

1. **Normal Flow**: Complete authorization and use tokens
2. **Token Expiration**: Wait for token to expire and observe auto-refresh
3. **Manual Refresh**: Use the refresh button before expiration
4. **Token Revocation**: Revoke tokens and re-authorize
5. **Session Recovery**: Close browser and return to test session persistence

### Customization

The interface uses Bootstrap 5 and can be easily customized:

- Modify CSS in the `<style>` section
- Update text and labels throughout the HTML
- Adjust token check interval (default: 30 seconds)

## Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the project on GitHub.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This is a demonstration project. Use it as a reference for implementing OAuth 2.0 clients with XAuthConnect.
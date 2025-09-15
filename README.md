# Sharokey JavaScript SDK

JavaScript library for secure secret sharing with Zero Knowledge encryption.

## Installation

```bash
npm install sharokey-js
```

Or install directly from GitHub:
```bash
npm install https://github.com/sharokey/sharokey-js
```

## Quick Start

```javascript
const { createClient } = require('sharokey-js');

// Create client
const client = createClient({
  apiUrl: 'https://your-sharokey-instance.com',
  domain: 'your-domain.com'
});

// Create a secret
const secret = await client.createSecret({
  content: 'My secret message',
  expirationTime: 3600, // 1 hour
  maxViews: 1
});

console.log(`Secret URL: ${secret.url}`);

// Retrieve a secret
const retrievedSecret = await client.getSecret('secret-uuid');
console.log(retrievedSecret.content);
```

## API Reference

### Client Configuration

```javascript
const client = createClient({
  apiUrl: 'https://your-instance.com',
  domain: 'your-domain.com',
  apiToken: 'your-api-token' // Optional for authenticated requests
});
```

### Creating Secrets

```javascript
const secret = await client.createSecret({
  content: 'Secret content',
  expirationTime: 3600, // seconds
  maxViews: 1,
  password: 'optional-password',
  allowedIps: ['192.168.1.1'] // Optional IP restriction
});
```

### Retrieving Secrets

```javascript
const secret = await client.getSecret(secretId, {
  password: 'password-if-required'
});
```

### Creating Secret Requests

```javascript
const request = await client.createSecretRequest({
  email: 'recipient@example.com',
  message: 'Please share the secret',
  expirationTime: 86400 // 24 hours
});
```

## Security Features

- **Zero Knowledge Encryption**: All secrets are encrypted client-side before transmission
- **AES-GCM Encryption**: Industry-standard encryption algorithm
- **Automatic Key Generation**: Secure random key generation
- **No Server-Side Decryption**: The server never has access to your unencrypted data

## Browser Compatibility

- Chrome/Edge 63+
- Firefox 57+
- Safari 11.1+
- Opera 50+

## License

MIT License

## Support

For support and documentation, visit: https://www.sharokey.com
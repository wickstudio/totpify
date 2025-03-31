# Totpify

*Advanced Time-Based One-Time Password (TOTP) Library*

[![npm version](https://img.shields.io/npm/v/totpify.svg?style=flat-square)](https://www.npmjs.org/package/totpify)
[![install size](https://packagephobia.com/badge?p=totpify)](https://packagephobia.com/result?p=totpify)
[![npm downloads](https://img.shields.io/npm/dm/totpify.svg?style=flat-square)](http://npm-stat.com/charts.html?package=totpify)
[![GitHub license](https://img.shields.io/github/license/wickstudio/totpify)](https://github.com/wickstudio/totpify/blob/master/LICENSE)

Totpify is a powerful library I built for generating and verifying Time-Based One-Time Passwords (TOTP), following RFC 6238. It's perfect for adding two-factor authentication to your apps, with support for different hash algorithms, QR code generation, and solid error handling.

## 📸 Screenshots

Here's what the live code generator looks like in action:

![Totpify Live Generator Screenshot](https://media.wickdev.me/9b4cb19233.png)

## 🔑 Features

- ✅ **Multiple Hash Algorithms** - SHA-1, SHA-256, and SHA-512 support
- ✅ **Automatic Base32 Handling** - No hassle with manual encoding/decoding
- ✅ **Time Drift Tolerance** - Handles device time sync issues like a champ
- ✅ **Solid Verification** - Full verification with time drift detection
- ✅ **QR Code Generation** - Super easy setup with authenticator apps
- ✅ **TypeScript Support** - Complete with type definitions
- ✅ **Great Error Handling** - Clear and helpful error messages
- ✅ **Performance** - Optimized for speed and efficiency
- ✅ **CLI Tool** - Command line access to all features

## 📦 Installation

Just grab it from npm:

```bash
# Using npm
npm install totpify

# Using yarn
yarn add totpify

# Using pnpm
pnpm add totpify
```

## 🚀 Quick Start

### Generate a TOTP Code

```js
const { generateTOTP } = require('totpify');

// Generate a code using the default SHA-1 algorithm
const secret = 'JBSWY3DPEHPK3PXP';
const code = generateTOTP(secret);
console.log(`TOTP Code: ${code}`);

// With options
const codeWithOptions = generateTOTP(secret, {
  algorithm: 'SHA-256',
  digits: 8,
  period: 30
});
console.log(`TOTP Code (8-digit, SHA-256): ${codeWithOptions}`);
```

### Verify a TOTP Code

```js
const { verifyTOTP } = require('totpify');

const secret = 'JBSWY3DPEHPK3PXP';
const userProvidedCode = '123456';

const result = verifyTOTP(userProvidedCode, secret, {
  window: 1, // Allow 1 step before and after (30 seconds each)
  algorithm: 'SHA-1'
});

if (result.valid) {
  console.log('Code is valid!');
  console.log(`Time drift: ${result.delta} periods`);
} else {
  console.log('Invalid code!');
}
```

### Generate a QR Code

```js
const { generateQRCode } = require('totpify');

const secret = 'JBSWY3DPEHPK3PXP';

// Generate a QR code for the user to scan with their authenticator app
generateQRCode(secret, {
  issuer: 'My App',
  account: 'user@example.com'
}).then(dataUrl => {
  console.log('QR Code (data URL):', dataUrl);
  // You can embed this data URL in an <img> tag
});
```

## 📋 API Documentation

### Core Functions

#### `generateTOTP(secret, options?)`

Generates a Time-Based One-Time Password.

**Parameters:**
- `secret` (string | Uint8Array): Base32 encoded secret or raw bytes
- `options` (object, optional):
  - `algorithm` ('SHA-1' | 'SHA-256' | 'SHA-512'): Hash algorithm (default: 'SHA-1')
  - `digits` (number): Number of digits (default: 6)
  - `period` (number): Token validity period in seconds (default: 30)
  - `timestamp` (number): Custom timestamp for code generation (default: current time)

**Returns:** string - The generated TOTP code

#### `verifyTOTP(token, secret, options?)`

Verifies a Time-Based One-Time Password.

**Parameters:**
- `token` (string): The TOTP code to verify
- `secret` (string | Uint8Array): Base32 encoded secret or raw bytes
- `options` (object, optional):
  - `algorithm` ('SHA-1' | 'SHA-256' | 'SHA-512'): Hash algorithm (default: 'SHA-1')
  - `digits` (number): Number of digits (default: 6)
  - `period` (number): Token validity period in seconds (default: 30)
  - `window` (number): Time drift window (default: 1)
  - `timestamp` (number): Custom timestamp for verification (default: current time)

**Returns:** object - `{ valid: boolean, delta?: number }`

#### `generateQRCode(secret, options?)`

Generates a QR code for easy setup with authenticator apps.

**Parameters:**
- `secret` (string): Base32 encoded secret
- `options` (object, optional):
  - `issuer` (string): Issuer name (default: 'Totpify')
  - `account` (string): Account name (default: 'user')
  - `width` (number): QR code width (default: 256)
  - `height` (number): QR code height (default: 256)

**Returns:** Promise<string> - Data URL containing the QR code

#### `generateRandomSecret(length?)`

Generates a random Base32 secret key.

**Parameters:**
- `length` (number, optional): Length of the secret key in bytes (default: 20)

**Returns:** string - Base32 encoded random secret

## 🖥️ Command Line Interface

The CLI tool is super handy for quick tests or scripting:

```bash
# Show help
totpify help

# Generate a TOTP code
totpify generate JBSWY3DPEHPK3PXP

# Generate with options
totpify generate JBSWY3DPEHPK3PXP --algorithm=SHA-256 --digits=8

# Verify a code
totpify verify 123456 JBSWY3DPEHPK3PXP

# Create a QR code
totpify qrcode JBSWY3DPEHPK3PXP --issuer=MyApp --account=user@example.com output.png

# Generate a random secret
totpify create-secret
```

## 📱 Compatible Services

Totpify works great with all the popular authenticator apps and services:

- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- LastPass
- Discord
- GitHub
- Gmail
- And tons more!

## 🧪 Advanced Examples

### Custom Time Period

```javascript
const { generateTOTP } = require('totpify');

// Generate a code with a 60-second period instead of the default 30 seconds
const code = generateTOTP('JBSWY3DPEHPK3PXP', { period: 60 });
```

### Using Different Hash Algorithms

```javascript
const { generateTOTP } = require('totpify');

const secret = 'JBSWY3DPEHPK3PXP';

// SHA-1 (default, compatible with most services)
const sha1Code = generateTOTP(secret, { algorithm: 'SHA-1' });

// SHA-256 (more secure)
const sha256Code = generateTOTP(secret, { algorithm: 'SHA-256' });

// SHA-512 (most secure)
const sha512Code = generateTOTP(secret, { algorithm: 'SHA-512' });

console.log(`SHA-1: ${sha1Code}`);
console.log(`SHA-256: ${sha256Code}`);
console.log(`SHA-512: ${sha512Code}`);
```

## Contributing

Got ideas? Contributions are welcome! Feel free to open issues or submit PRs.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/cool-feature`)
3. Commit your changes (`git commit -m 'Add some cool feature'`)
4. Push to the branch (`git push origin feature/cool-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact

- GitHub: [wickstudio](https://github.com/wickstudio)
- Discord: [discord.gg/wicks](https://discord.gg/wicks)
- Email: [info@wick-studio.com](mailto:info@wick-studio.com)

---

Made with ❤️ by [Wick Studio](https://github.com/wickstudio)
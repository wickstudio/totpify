# Totpify

<p align="center">
  <img src="https://i.imgur.com/xuw3IHA.png" alt="Totpify Logo" width="220" />
</p>

Advanced TOTP tooling for Node.js with TypeScript support, otpauth helpers, recovery codes, and setup-ready enrollment bundles.

[![npm version](https://img.shields.io/npm/v/totpify.svg?style=flat-square)](https://www.npmjs.org/package/totpify)
[![install size](https://packagephobia.com/badge?p=totpify)](https://packagephobia.com/result?p=totpify)
![CI](https://github.com/wickstudio/totpify/actions/workflows/node.yml/badge.svg)
[![npm downloads](https://img.shields.io/npm/dm/totpify.svg?style=flat-square)](http://npm-stat.com/charts.html?package=totpify)
[![GitHub license](https://img.shields.io/github/license/wickstudio/totpify)](https://github.com/wickstudio/totpify/blob/master/LICENSE)

`totpify` started as a TOTP utility library and now covers a much more useful slice of real 2FA workflows:

- TOTP generation and verification
- HOTP generation
- Base32 encode and decode helpers
- otpauth URI generation and parsing
- QR code generation for authenticator app onboarding
- recovery code generation, hashing, and verification
- enrollment bundles that package secrets, QR setup, and recovery assets together
- policy-driven async verification with replay protection hooks
- CLI commands for day-to-day OTP tasks

If you are building login flows, admin dashboards, internal tools, bots, or support tooling, `totpify` is designed to save you from stitching all of this together by hand.

## Highlights

- Supports `SHA-1`, `SHA-256`, and `SHA-512`
- Uses timing-safe comparison during TOTP verification
- Validates digits, periods, timestamps, windows, and secrets at runtime
- Accepts `bigint` counters for HOTP generation
- Generates full `otpauth://` URIs with algorithm, digits, and period
- Produces recovery codes ready for secure storage with `scrypt`
- Ships a higher-level enrollment flow for setup screens and account onboarding
- Includes policy presets, replay-store hooks, and safe verification diagnostics

## Why Totpify

`totpify` is designed for teams that need more than token math:

- It covers the full onboarding path, not just code generation.
- It includes recovery-code and enrollment flows that usually have to be built separately.
- It adds policy-driven verification and replay-protection hooks for production auth systems.
- It exposes machine-readable verification results that are useful in APIs, logs, and admin tools.
- It ships a CLI that is useful for debugging, support, and manual operational checks.

If you only need a minimal TOTP helper, smaller packages are fine. If you want one package that reaches further into real 2FA workflows, `totpify` is aimed at that gap.

For a practical authenticator-app guide, see [Authenticator Compatibility Guide](https://github.com/wickstudio/totpify/blob/master/docs/compatibility.md).

## Comparison

Comparison below is based on the public package docs linked in the notes after the table and was reviewed on April 13, 2026.

| Capability | `totpify` | `speakeasy` | `otplib` |
| --- | --- | --- | --- |
| TOTP generation | Yes | Yes | Yes |
| HOTP generation | Yes | Yes | Yes |
| Base32 encode/decode helpers | Yes | Partial | Yes |
| otpauth URI generation | Yes | Yes | Yes |
| otpauth URI parsing | Yes | No documented parser | Yes |
| QR code generation | Yes, built-in | External QR library | External QR library |
| Recovery codes | Yes | No | No |
| Enrollment bundles | Yes | No | No |
| Policy-driven verification | Yes | No | No |
| Replay protection hooks | Yes | No | No |
| CLI support | Yes, built-in | No official CLI documented | No official CLI documented |
| Diagnostics / machine-readable reasons | Yes | Partial | No documented reason codes |
| Framework adapters | No official adapters yet | No official adapters documented | No official adapters documented |
| TypeScript support | Yes, built-in | Community typings | Yes, built-in |

Comparison notes:

- For `speakeasy`, "Partial" on Base32 means the docs show Base32 secret output via `generateSecret`, but they do not document generic public encode/decode helpers.
- For `speakeasy`, "Partial" on diagnostics refers to `verifyDelta()` returning a delta, not higher-level reason codes like `expired` or `replay_detected`.
- For `otplib`, URI generation/parsing is part of the official ecosystem and documented through `otplib` and `@otplib/uri`.
- For both `speakeasy` and `otplib`, QR code generation is documented using an external QR package rather than being built into the core library.

Comparison sources:

- `speakeasy`: https://github.com/speakeasyjs/libotp
- `@types/speakeasy`: https://www.npmjs.com/package/%40types/speakeasy
- `otplib`: https://otplib.yeojz.dev/api/otplib/
- `@otplib/uri`: https://otplib.yeojz.dev/api/%40otplib/uri/

## Installation

```bash
npm install totpify
```

Node.js `18+` is recommended.

## Quick Start

### Generate and verify a TOTP code

```js
const { generateTOTP, verifyTOTP } = require('totpify');

const secret = 'JBSWY3DPEHPK3PXP';
const code = generateTOTP(secret, {
  algorithm: 'SHA-256',
  digits: 6,
  period: 30,
});

const result = verifyTOTP(code, secret, {
  algorithm: 'SHA-256',
  digits: 6,
  period: 30,
  window: 1,
});

console.log(code);
console.log(result);
```

### Create a full enrollment bundle

```js
const { createEnrollmentBundle } = require('totpify');

async function main() {
  const bundle = await createEnrollmentBundle({
    issuer: 'Acme',
    account: 'ops@acme.com',
    secretByteLength: 20,
    algorithm: 'SHA-256',
    digits: 8,
    period: 30,
    recoveryCodes: { count: 6 },
  });

  console.log(bundle.secret);
  console.log(bundle.otpauthUri);
  console.log(bundle.qrCodeDataUrl);
  console.log(bundle.recoveryCodes);
}

main();
```

### Use policy-driven advanced verification

```js
const {
  createVerifier,
  MemoryReplayStore,
} = require('totpify');

async function main() {
  const verifier = createVerifier({
    policy: 'admin',
    replayStore: new MemoryReplayStore(),
    diagnostics: 'safe',
    onEvent(event) {
      console.log(event);
    },
  });

  const result = await verifier.verify({
    token: '123456',
    secret: 'JBSWY3DPEHPK3PXP',
    factorId: 'otp_factor_1',
    subject: 'user_42',
    context: {
      ip: '203.0.113.10',
      route: '/login/verify-otp',
    },
  });

  console.log(result);
}

main();
```

> Warning
>
> `MemoryReplayStore` is mainly for development, tests, demos, or single-process deployments.
> It is not the recommended production replay-protection mechanism.
> In production, use a shared backing store such as Redis or a database so replay detection works across processes and instances.

### Generate and store recovery codes

```js
const {
  createRecoveryCodeSet,
  verifyRecoveryCode,
} = require('totpify');

const recoverySet = createRecoveryCodeSet({ count: 8 });

console.log(recoverySet.codes);
console.log(recoverySet.hashes);

const isValid = verifyRecoveryCode(recoverySet.codes[0], recoverySet.hashes[0]);
console.log(isValid);
```

### Work with otpauth URIs directly

```js
const {
  generateOtpauthUri,
  parseOtpauthUri,
} = require('totpify');

const uri = generateOtpauthUri('JBSWY3DPEHPK3PXP', {
  issuer: 'Acme',
  account: 'user@example.com',
  algorithm: 'SHA-512',
  digits: 8,
  period: 45,
});

const parsed = parseOtpauthUri(uri);

console.log(uri);
console.log(parsed);
```

## Current API

### Core OTP

- `generateTOTP(secret, options?)`
- `verifyTOTP(token, secret, options?)`
- `generateHOTP(secretBytes, counter, algorithm?, digits?)`
- `generateRandomSecret(length?)`

`generateRandomSecret(length?)` treats `length` as the number of random bytes before Base32 encoding.

Example:

```js
const { generateRandomSecret } = require('totpify');

const secret = generateRandomSecret(20);
console.log(secret);
```

### Base32

- `encodeBase32(bytes)`
- `decodeBase32(secret)`

### otpauth and QR

- `generateOtpauthUri(secret, options?)`
- `parseOtpauthUri(uri)`
- `generateQRCode(secret, options?)`

### Recovery Codes

- `generateRecoveryCodes(options?)`
- `hashRecoveryCode(code, options?)`
- `verifyRecoveryCode(code, hash)`
- `createRecoveryCodeSet(options?, hashOptions?)`

### Enrollment

- `createEnrollmentBundle(options?)`

### Advanced Verification

- `createVerifier(options?)`
- `resolveVerificationPolicy(policy, basePolicy?)`
- `verificationPolicies`
- `MemoryReplayStore`

The enrollment bundle returns:

- `secret`
- `secretBytes`
- `otpauthUri`
- `qrCodeDataUrl`
- `recoveryCodes`
- `recoveryCodeHashes`
- OTP metadata such as algorithm, digits, period, issuer, and account

## Options Reference

### `TOTPOptions`

- `algorithm`: `'SHA-1' | 'SHA-256' | 'SHA-512'`
- `digits`: integer from `6` to `10`
- `period`: positive integer in seconds
- `timestamp`: timestamp in milliseconds
- `window`: non-negative integer verification window

### `OtpauthUriOptions`

- `issuer`
- `account`
- `algorithm`
- `digits`
- `period`

### `RecoveryCodeOptions`

- `count`: number of recovery codes to generate
- `segments`: number of groups in each code
- `segmentLength`: characters per group
- `separator`: group separator, default `-`

### `EnrollmentBundleOptions`

- `issuer`
- `account`
- `secret`
- `secretBytes`
- `secretByteLength`
- `algorithm`
- `digits`
- `period`
- `qrCode`
- `recoveryCodes`

### `CreateVerifierOptions`

- `policy`: `'strict' | 'balanced' | 'admin'` or policy overrides
- `replayStore`: pluggable replay protection store
- `diagnostics`: `off`, `safe`, or `debug`
- `onEvent`: structured verification event hook

### Verification Reasons

The advanced verifier uses machine-readable reasons:

- `valid`
- `invalid_format`
- `invalid_token`
- `expired`
- `future_skew`
- `replay_detected`
- `policy_blocked`

## CLI

After installing globally or using `npx`, `totpify` includes a CLI for common operations.

```bash
# Show help
totpify help

# Generate a TOTP code
totpify generate JBSWY3DPEHPK3PXP

# Verify a code
totpify verify 123456 JBSWY3DPEHPK3PXP

# Generate a QR code as a data URL
totpify qrcode JBSWY3DPEHPK3PXP --issuer=Acme --account=user@example.com

# Save a QR code to a file
totpify qrcode JBSWY3DPEHPK3PXP --issuer=Acme --account=user@example.com setup.png

# Generate a Base32 secret from 20 random bytes
totpify create-secret 20

# Generate recovery codes
totpify recovery-codes 8
```

### CLI output examples

Successful verification:

```bash
$ totpify verify 123456 JBSWY3DPEHPK3PXP
Valid (time drift: 0 periods)
```

Failed verification:

```bash
$ totpify verify 000000 JBSWY3DPEHPK3PXP
Invalid code
```

QR generation to stdout:

```bash
$ totpify qrcode JBSWY3DPEHPK3PXP --issuer=Acme --account=user@example.com
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...
```

QR generation to a file:

```bash
$ totpify qrcode JBSWY3DPEHPK3PXP --issuer=Acme --account=user@example.com setup.png
QR code saved to setup.png
```

Recovery code generation:

```bash
$ totpify recovery-codes 3
8J4QW-M7Y2P
K9TXV-2N8CD
R6WQP-H3M7K
```

Notes:

- Recovery codes are random, so the exact values will differ on each run.
- Successful verification prints the same format shown above; the drift value can be non-zero if you are near a time-step boundary.

## Standards

`totpify` implements the two main OATH OTP standards used by mainstream authenticator apps and services:

- RFC 4226 for HOTP
- RFC 6238 for TOTP

The test suite includes official standards vectors for both:

- RFC 4226 Appendix D HOTP test vectors
- RFC 6238 Appendix B TOTP test vectors

Those vectors are validated in [`__tests__/totp.test.ts`](./__tests__/totp.test.ts).

## Environment Support

Support status below is intentionally conservative and reflects what is actually validated in this repository today.

| Environment | Status | Notes |
| --- | --- | --- |
| Node.js | Supported and tested | `package.json` declares `>=18.0.0`. Build and test were verified locally on April 13, 2026 with Node `v24.14.0`. |
| Browser | Not officially supported | The current implementation still depends on Node-oriented `crypto` and `Buffer` paths for OTP and recovery flows. |
| Bun | Untested | `bun` was not available in the validation environment for this pass, so no support claim is made. |
| Deno | Untested | `deno` was not available in the validation environment for this pass, so no support claim is made. |
| Edge runtimes | Not officially supported | The current package output and crypto assumptions are Node-centric. |

For authenticator app notes and a repeatable device-validation checklist, see [docs/compatibility.md](https://github.com/wickstudio/totpify/blob/master/docs/compatibility.md).

## Real-World Use Cases

`totpify` is already useful for more than just basic OTP math:

- login and signup flows with authenticator app enrollment
- admin dashboards that need one-click QR provisioning
- support tooling that issues or rotates recovery codes
- internal systems that need strong operator 2FA
- bots and CLIs that prompt for OTP verification
- account setup flows that need a single payload containing everything required for onboarding

## Security Notes

`totpify` now bakes in a few important best practices:

- TOTP verification uses timing-safe comparison
- recovery code hashes are derived with `scrypt`
- otpauth URIs validate secrets before generating setup payloads
- token settings are validated instead of silently accepted
- advanced verification can enforce replay protection with a pluggable store

You should still handle a few things at the application layer:

- encrypt or otherwise protect stored TOTP secrets
- store only hashed recovery codes
- add replay protection if you want to block reuse within the same time step
- audit failed verification attempts in your own auth system
- rate-limit verification endpoints

For production use, the recommended path is:

1. Use `createVerifier()` instead of wiring drift and replay checks yourself.
2. Pick a preset policy and override only what you must.
3. Back replay protection with a shared store such as Redis or your database.
4. Persist only recovery code hashes, not raw recovery codes.

## Testing and Quality

The package currently includes coverage for:

- TOTP generation and verification
- RFC 4226 HOTP vectors
- RFC 6238 TOTP vectors
- Base32 round-trips
- QR generation
- otpauth URI generation and parsing
- recovery code creation and hashing
- enrollment bundle creation
- CLI behavior
- advanced verifier policies, replay detection, and diagnostics

## Roadmap

The library is already more capable than a plain OTP helper, but there is still room to make it stand out further:

- policy presets like `strict`, `balanced`, and `admin`
- replay detection hooks
- shared-store replay adapters
- recovery code consumption helpers
- secret rotation and migration flows
- framework adapters for Express, Fastify, NestJS, and Next.js
- audit-safe diagnostics and event hooks
- tenant-aware enrollment defaults

## Contributing

Issues and pull requests are welcome. The most valuable contributions right now are:

- interoperability tests with real authenticator apps
- replay-protection primitives
- framework integration packages
- deeper recovery and operator workflows
- documentation improvements and deployment examples

## License

MIT

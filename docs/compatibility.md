# Authenticator Compatibility Guide

This guide is for teams who want to validate `totpify` against mainstream authenticator apps before shipping a production enrollment flow.

It separates three things clearly:

- what `totpify` generates today
- what the app vendors publicly document
- what still needs hands-on device validation in your own environment

## Current `totpify` provisioning baseline

For the widest authenticator compatibility, the safest baseline profile is:

- algorithm: `SHA-1`
- digits: `6`
- period: `30`

That is also the library default for TOTP provisioning helpers unless you override it.

The generated `otpauth://` URI includes:

- label in the form `issuer:account`
- `secret`
- `issuer`
- `algorithm`
- `digits`
- `period`

If you need the least surprising experience across authenticator apps, start with the default baseline above and only move away from it when you have validated the target app behavior yourself.

## Compatibility summary

The table below reflects vendor documentation reviewed on April 13, 2026 plus the current `totpify` provisioning format.

| App | QR onboarding | Manual entry | Recommended `totpify` profile | Notes |
| --- | --- | --- | --- | --- |
| Google Authenticator | Yes | Yes | `SHA-1`, `6`, `30` | Google’s URI guidance notes that some implementations may ignore non-default algorithm, digits, or period fields. |
| Microsoft Authenticator | Yes | Yes | `SHA-1`, `6`, `30` | Microsoft documents QR and manual setup for non-Microsoft accounts. |
| Authy | Yes | Vendor docs show QR-based setup | `SHA-1`, `6`, `30` | Use standard TOTP provisioning and validate final UX on the device you support. |
| 1Password | Yes | Yes | `SHA-1`, `6`, `30` | 1Password supports scanning QR codes and adding one-time password secrets manually. |
| Bitwarden | Yes | Yes | `SHA-1`, `6`, `30` | Included here as an extra common target. Bitwarden documents otpauth-style TOTP setup and an integrated authenticator flow. |

## What is backed by this repository

From the code and tests in this repository:

- `totpify` generates a standard `otpauth://totp/...` URI.
- The default provisioning values are `SHA-1`, `6`, and `30`.
- QR output is generated from the full otpauth URI.
- RFC 4226 HOTP vectors are tested.
- RFC 6238 TOTP vectors are tested.

That gives a good protocol-level baseline, but it is not the same thing as a real-device acceptance test.

## Manual validation workflow

Use this exact flow when testing with a real authenticator app:

1. Generate a fresh secret:

```bash
node dist/cli.js create-secret 20
```

2. Generate a QR file with compatibility-friendly defaults:

```bash
node dist/cli.js qrcode YOUR_SECRET --issuer=TotpifyDemo --account=you@example.com compatibility-test.png
```

3. Scan `compatibility-test.png` with the target authenticator app.

4. Generate the current expected code locally:

```bash
node dist/cli.js generate YOUR_SECRET
```

5. Compare the app code with the local output inside the same 30-second window.

6. Validate verification:

```bash
node dist/cli.js verify APP_CODE YOUR_SECRET
```

7. Confirm that verification prints:

```bash
Valid (time drift: 0 periods)
```

Small drift values are still expected if you are close to a time-step boundary.

## Real-device checklist

When you do a real compatibility pass, record the following for each app:

- app name and platform
- app version
- device OS version
- whether QR scan worked
- whether manual entry worked
- whether the app displayed the expected issuer/account label
- whether the generated code matched `totpify generate`
- whether `totpify verify` accepted the live code
- whether any app-specific quirks appeared

Suggested result table:

| App | Platform | QR scan | Manual entry | Code matched | Verify passed | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Google Authenticator | iOS / Android | Pending | Pending | Pending | Pending | Fill after device test |
| Microsoft Authenticator | iOS / Android | Pending | Pending | Pending | Pending | Fill after device test |
| Authy | iOS / Android / Desktop | Pending | Pending | Pending | Pending | Fill after device test |
| 1Password | iOS / Android / Desktop | Pending | Pending | Pending | Pending | Fill after device test |
| Bitwarden | iOS / Android / Desktop | Pending | Pending | Pending | Pending | Fill after device test |

## Screenshot capture plan

No authenticator-app screenshots are committed in this repository yet because this pass was completed without access to real devices or installed authenticator apps.

If you want to add screenshot evidence later, capture these and store them under `docs/assets/compatibility/`:

- `google-authenticator-qr-scan.png`
- `google-authenticator-code-view.png`
- `microsoft-authenticator-qr-scan.png`
- `authy-code-view.png`
- `1password-code-view.png`
- `bitwarden-code-view.png`

Recommended screenshot set for each app:

- the scanned account entry screen
- the generated live code screen
- any manual-entry screen if the app exposes one

## App-specific notes

### Google Authenticator

Use the default `SHA-1 / 6 / 30` profile unless you have tested custom settings on the exact app versions you care about.

Google’s Key URI guidance is the most relevant baseline for interoperable TOTP provisioning. It explicitly calls out that not every app handles `algorithm`, `digits`, and `period` consistently, so conservative defaults are best for broad compatibility.

### Microsoft Authenticator

Microsoft documents QR and manual setup for non-Microsoft accounts. For the lowest-friction setup, use the same conservative profile: `SHA-1 / 6 / 30`.

### Authy

Twilio’s Authy documentation supports QR-based onboarding flows. Standard TOTP provisioning is the right starting point, but if Authy is a critical target for your users, validate the exact onboarding UX on the platforms you support.

### 1Password

1Password documents one-time password setup by scanning a QR code or adding the secret manually. `totpify`’s URI and QR output fit naturally into that flow.

### Bitwarden

Bitwarden documents TOTP setup and authenticator usage, and it is a useful extra interoperability target even though it is not strictly required for this guide.

## Recommended production defaults

If you are shipping to a broad user base and do not control the authenticator app:

- keep provisioning on `SHA-1`
- keep codes at `6` digits
- keep period at `30` seconds
- use issuer and account labels that are stable and human-readable
- validate your final QR flow on at least one Android app and one iOS app before release

If you move to custom algorithms, custom digit lengths, or custom periods, treat that as a compatibility decision and test it explicitly.

## Sources

- Google Authenticator Key URI Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- Microsoft Authenticator setup for non-Microsoft accounts: https://support.microsoft.com/en-us/account-billing/set-up-the-microsoft-authenticator-app-as-your-verification-method-33452159-6af9-438f-8f82-63ce94cf3d29
- Twilio Authy installation and app setup guidance: https://help.twilio.com/articles/19753637085467-How-to-Download-and-Install-Authy-Apps
- Twilio blog on interoperable authenticator apps: https://www.twilio.com/en-us/blog/developers/tutorials/product/authy-api-and-google-authenticator
- 1Password one-time password setup: https://support.1password.com/guides/mac/totp.html
- Bitwarden integrated authenticator: https://bitwarden.com/help/integrated-authenticator/
- Bitwarden Authenticator overview: https://bitwarden.com/help/bitwarden-authenticator/

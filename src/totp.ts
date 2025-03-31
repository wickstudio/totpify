import { TOTPOptions, VerifyResult, HashAlgorithm, QRCodeOptions } from './types';
import { decodeBase32, generateHOTP, getCurrentTimestamp, normalizeSecret, getHashFunction } from './utils';
import * as QRCode from 'qrcode';

/**
 * Generates a Time-Based One-Time Password (TOTP) according to RFC 623
 * @param secret The secret key as a string (Base32 encoded) or a Uint8Array
 * @param options Options for TOTP generation
 * @returns The generated TOTP code
 */

export function generateTOTP(
  secret: string | Uint8Array,
  options: TOTPOptions = {}
): string {
  const {
    algorithm = 'SHA-1',
    digits = 6,
    period = 30,
    timestamp = Date.now()
  } = options;

  if (!secret) {
    throw new Error('Secret must be provided');
  }

  let secretBytes: Uint8Array;
  if (typeof secret === 'string') {
    try {
      secretBytes = decodeBase32(secret);
    } catch (error) {
      throw new Error(`Invalid secret: ${(error as Error).message}`);
    }
  } else {
    secretBytes = secret;
  }

  const counter = Math.floor(timestamp / 1000 / period);
  
  return generateHOTP(secretBytes, counter, algorithm, digits);
}

/**
 * Verifies a Time-Based One-Time Password (TOTP) allowing for time skew
 * @param token The TOTP code to verify
 * @param secret The secret key as a string (Base32 encoded) or a Uint8Array
 * @param options Options for TOTP verification
 * @returns Result object with valid flag and time drift information
 */

export function verifyTOTP(
  token: string,
  secret: string | Uint8Array,
  options: TOTPOptions = {}
): VerifyResult {
  const {
    window = 1,
    algorithm = 'SHA-1',
    digits = 6,
    period = 30,
    timestamp = Date.now()
  } = options;

  if (!token || token.length !== digits || !/^\d+$/.test(token)) {
    return { valid: false };
  }

  for (let i = -window; i <= window; i++) {
    const checkTime = timestamp + i * period * 1000;
    const generatedToken = generateTOTP(secret, {
      algorithm,
      digits,
      period,
      timestamp: checkTime,
    });

    if (generatedToken === token) {
      return { valid: true, delta: i };
    }
  }

  return { valid: false };
}

/**
 * Generates a QR code for easy TOTP setup with authenticator apps.
 * The QR code follows the 'otpauth://' URI format.
 * @param secret The secret key (Base32 encoded)
 * @param options Options for QR code generation
 * @returns Promise resolving to a data URL containing the QR code
 */

export async function generateQRCode(
  secret: string,
  options: QRCodeOptions = {}
): Promise<string> {
  const {
    issuer = 'Totpify',
    account = 'user',
    width = 256,
    height = 256,
  } = options;

  const normalizedSecret = normalizeSecret(secret);
  
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(account);
  
  const uri = `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${normalizedSecret}&issuer=${encodedIssuer}`;

  try {
    return await QRCode.toDataURL(uri, { 
      errorCorrectionLevel: 'H',
      type: 'image/png',
      margin: 1,
      width 
    });
  } catch (error) {
    throw new Error(`QR code generation failed: ${(error as Error).message}`);
  }
}

/**
 * Generates a random secret key in Base32 format for use with TOTP
 * @param length The length of the secret key in bytes (default: 20)
 * @returns Base32 encoded random secret
 */

export function generateRandomSecret(length: number = 20): string {
  const randomBytes = new Uint8Array(length);
  
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(randomBytes);
  } else {
    const crypto = require('crypto');
    randomBytes.set(crypto.randomBytes(length));
  }
  
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += base32Chars[randomBytes[i] % base32Chars.length];
  }
  
  return result;
}
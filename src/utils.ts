import { HashAlgorithm } from './types';

export function normalizeSecret(secret: string): string {
  return secret.replace(/\s+/g, '').toUpperCase();
}

export function normalizeRecoveryCode(code: string): string {
  return code.replace(/[\s-]+/g, '').toUpperCase();
}

export function encodeBase32(bytes: Uint8Array): string {
  if (!bytes.length) {
    throw new Error('Cannot encode an empty byte array');
  }

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let index = 0; index < bytes.length; index++) {
    value = (value << 8) | bytes[index];
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

export function decodeBase32(base32: string): Uint8Array {
  const normalizedKey = normalizeSecret(base32).replace(/=+$/, '');
  
  if (normalizedKey.length === 0) {
    throw new Error('Empty Base32 string');
  }
  
  if (!/^[A-Z2-7]+$/.test(normalizedKey)) {
    throw new Error('Invalid base32 character in key');
  }

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  
  let bits = 0;
  let value = 0;
  const result: number[] = [];
  
  for (let i = 0; i < normalizedKey.length; i++) {
    const char = normalizedKey.charAt(i);
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    
    if (bits >= 8) {
      result.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  
  return new Uint8Array(result);
}

export function generateHOTP(
  key: Uint8Array,
  counter: number | bigint,
  algorithm: HashAlgorithm = 'SHA-1',
  digits: number = 6
): string {
  assertSecretBytes(key);
  assertDigits(digits);

  const crypto = getNodeCrypto();
  const counterBuffer = getCounterBuffer(counter);
  
  const algoMap: Record<HashAlgorithm, string> = {
    'SHA-1': 'sha1',
    'SHA-256': 'sha256',
    'SHA-512': 'sha512'
  };
  
  const hmac = crypto.createHmac(algoMap[algorithm], Buffer.from(key));
  const digest = hmac.update(Buffer.from(counterBuffer)).digest();
  
  const offset = digest[digest.length - 1] & 0x0f;
  
  const binary = 
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, digits);
  
  return otp.toString().padStart(digits, '0');
}

export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

export function getHashFunction(algorithm: HashAlgorithm): string {
  switch (algorithm) {
    case 'SHA-1':
      return 'sha1';
    case 'SHA-256':
      return 'sha256';
    case 'SHA-512':
      return 'sha512';
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

export function mapOtpauthAlgorithm(algorithm: HashAlgorithm): string {
  return getHashFunction(algorithm).toUpperCase();
}

export function getNodeCrypto(): typeof import('crypto') {
  try {
    return require('crypto');
  } catch (error) {
    throw new Error('Node.js crypto library is required for cryptographic operations');
  }
}

export function getRandomBytes(length: number): Uint8Array {
  assertPositiveInteger('length', length);

  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    const randomBytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(randomBytes);
    return randomBytes;
  }

  const crypto = getNodeCrypto();
  return new Uint8Array(crypto.randomBytes(length));
}

export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }

  const crypto = getNodeCrypto();
  return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

export function assertDigits(digits: number): void {
  assertPositiveInteger('digits', digits);

  if (digits < 6 || digits > 10) {
    throw new Error('Digits must be between 6 and 10');
  }
}

export function assertPeriod(period: number): void {
  assertPositiveInteger('period', period);
}

export function assertWindow(window: number): void {
  if (!Number.isInteger(window) || window < 0) {
    throw new Error('Window must be a non-negative integer');
  }
}

export function assertTimestamp(timestamp: number): void {
  if (!Number.isFinite(timestamp) || timestamp < 0) {
    throw new Error('Timestamp must be a non-negative number');
  }
}

export function assertSecretBytes(secret: Uint8Array): void {
  if (!secret.length) {
    throw new Error('Secret must not be empty');
  }
}

export function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
}

function getCounterBuffer(counter: number | bigint): Uint8Array {
  let value: bigint;

  if (typeof counter === 'bigint') {
    value = counter;
  } else {
    if (!Number.isSafeInteger(counter) || counter < 0) {
      throw new Error('Counter must be a non-negative safe integer or bigint');
    }

    value = BigInt(counter);
  }

  const counterBuffer = new Uint8Array(8);

  for (let index = 7; index >= 0; index--) {
    counterBuffer[index] = Number(value & 0xffn);
    value >>= 8n;
  }

  if (value !== 0n) {
    throw new Error('Counter must fit within 8 bytes');
  }

  return counterBuffer;
}

import { HashAlgorithm } from './types';

export function normalizeSecret(secret: string): string {
  return secret.replace(/\s+/g, '').toUpperCase();
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
  counter: number,
  algorithm: HashAlgorithm = 'SHA-1',
  digits: number = 6
): string {
  let crypto;
  
  try {
    crypto = require('crypto');
  } catch (e) {
    throw new Error('Node.js crypto library is required for HMAC operations');
  }
  
  const counterBuffer = new Uint8Array(8);
  let tempCounter = counter;
  
  for (let i = 7; i >= 0; i--) {
    counterBuffer[i] = tempCounter & 0xff;
    tempCounter = tempCounter >>> 8;
  }
  
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
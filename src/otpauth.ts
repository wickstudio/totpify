import * as QRCode from 'qrcode';
import { HashAlgorithm, OtpauthUriOptions, ParsedOtpauthUri, QRCodeOptions } from './types';
import {
  assertDigits,
  assertPeriod,
  decodeBase32,
  mapOtpauthAlgorithm,
  normalizeSecret,
} from './utils';

function getLabel(issuer: string, account: string): string {
  return `${issuer}:${account}`;
}

export function generateOtpauthUri(
  secret: string,
  options: OtpauthUriOptions = {}
): string {
  const {
    issuer = 'Totpify',
    account = 'user',
    algorithm = 'SHA-1',
    digits = 6,
    period = 30,
  } = options;

  const normalizedSecret = normalizeSecret(secret);

  if (!normalizedSecret) {
    throw new Error('Secret must be provided');
  }

  decodeBase32(normalizedSecret);

  assertDigits(digits);
  assertPeriod(period);

  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(account);
  const encodedSecret = encodeURIComponent(normalizedSecret);
  const encodedAlgorithm = encodeURIComponent(mapOtpauthAlgorithm(algorithm));

  return `otpauth://totp/${encodeURIComponent(getLabel(issuer, account))}?secret=${encodedSecret}&issuer=${encodedIssuer}&algorithm=${encodedAlgorithm}&digits=${digits}&period=${period}`;
}

export function parseOtpauthUri(uri: string): ParsedOtpauthUri {
  let parsed: URL;

  try {
    parsed = new URL(uri);
  } catch (error) {
    throw new Error(`Invalid otpauth URI: ${(error as Error).message}`);
  }

  if (parsed.protocol !== 'otpauth:') {
    throw new Error('Invalid otpauth URI: unsupported protocol');
  }

  if (parsed.hostname.toLowerCase() !== 'totp') {
    throw new Error('Invalid otpauth URI: unsupported OTP type');
  }

  const secret = normalizeSecret(parsed.searchParams.get('secret') || '');

  if (!secret) {
    throw new Error('Invalid otpauth URI: secret is required');
  }

  decodeBase32(secret);

  const rawLabel = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  const [issuerFromLabel = '', ...accountParts] = rawLabel.split(':');
  const accountFromLabel = accountParts.join(':');

  const issuer = parsed.searchParams.get('issuer') || issuerFromLabel || 'Totpify';
  const account = accountFromLabel || 'user';
  const algorithm = getHashFunctionFromOtpauth(
    parsed.searchParams.get('algorithm') || 'SHA1'
  );
  const digits = Number(parsed.searchParams.get('digits') || '6');
  const period = Number(parsed.searchParams.get('period') || '30');

  assertDigits(digits);
  assertPeriod(period);

  return {
    type: 'totp',
    label: rawLabel,
    issuer,
    account,
    secret,
    algorithm,
    digits,
    period,
  };
}

export async function generateQRCodeDataUrl(
  uri: string,
  options: Pick<QRCodeOptions, 'width' | 'height'> = {}
): Promise<string> {
  const { width = 256, height } = options;
  const size = typeof height === 'number' ? Math.min(width, height) : width;

  try {
    return await QRCode.toDataURL(uri, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      margin: 1,
      width: size,
    });
  } catch (error) {
    throw new Error(`QR code generation failed: ${(error as Error).message}`);
  }
}

function getHashFunctionFromOtpauth(value: string): HashAlgorithm {
  const normalizedValue = value.toUpperCase();

  switch (normalizedValue) {
    case 'SHA1':
      return 'SHA-1';
    case 'SHA256':
      return 'SHA-256';
    case 'SHA512':
      return 'SHA-512';
    default:
      throw new Error(`Invalid otpauth URI: unsupported algorithm ${value}`);
  }
}

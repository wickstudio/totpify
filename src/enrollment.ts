import { createRecoveryCodeSet } from './recovery';
import { EnrollmentBundle, EnrollmentBundleOptions } from './types';
import { decodeBase32, encodeBase32, getRandomBytes } from './utils';
import { generateOtpauthUri, generateQRCodeDataUrl } from './otpauth';

export async function createEnrollmentBundle(
  options: EnrollmentBundleOptions = {}
): Promise<EnrollmentBundle> {
  const {
    issuer = 'Totpify',
    account = 'user',
    secret,
    secretBytes,
    secretByteLength,
    algorithm = 'SHA-1',
    digits = 6,
    period = 30,
    qrCode = true,
    recoveryCodes = false,
  } = options;

  const requestedSecretByteLength = secretByteLength ?? secretBytes ?? 20;
  const generatedSecretBytes = secret ? undefined : getRandomBytes(requestedSecretByteLength);
  const resolvedSecret = secret || encodeBase32(generatedSecretBytes as Uint8Array);
  const resolvedSecretBytes = secret ? decodeBase32(secret) : (generatedSecretBytes as Uint8Array);
  const otpauthUri = generateOtpauthUri(resolvedSecret, {
    issuer,
    account,
    algorithm,
    digits,
    period,
  });

  const bundle: EnrollmentBundle = {
    issuer,
    account,
    secret: resolvedSecret,
    secretBytes: resolvedSecretBytes,
    otpauthUri,
    algorithm,
    digits,
    period,
    createdAt: Date.now(),
  };

  if (qrCode) {
    const qrOptions = typeof qrCode === 'object' ? qrCode : {};
    bundle.qrCodeDataUrl = await generateQRCodeDataUrl(otpauthUri, qrOptions);
  }

  if (recoveryCodes) {
    const recoveryOptions = typeof recoveryCodes === 'object' ? recoveryCodes : {};
    const recoverySet = createRecoveryCodeSet(recoveryOptions);
    bundle.recoveryCodes = recoverySet.codes;
    bundle.recoveryCodeHashes = recoverySet.hashes;
  }

  return bundle;
}

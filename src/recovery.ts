import { RecoveryCodeHashOptions, RecoveryCodeOptions, RecoveryCodeSet } from './types';
import {
  assertPositiveInteger,
  constantTimeEqual,
  getNodeCrypto,
  getRandomBytes,
  normalizeRecoveryCode,
} from './utils';

const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_CODE_HASH_PREFIX = 'scrypt';

export function generateRecoveryCodes(options: RecoveryCodeOptions = {}): string[] {
  const {
    count = 8,
    segments = 2,
    segmentLength = 5,
    separator = '-',
  } = options;

  assertPositiveInteger('count', count);
  assertPositiveInteger('segments', segments);
  assertPositiveInteger('segmentLength', segmentLength);

  const codeLength = segments * segmentLength;
  const codes: string[] = [];

  for (let index = 0; index < count; index++) {
    const randomBytes = getRandomBytes(codeLength);
    let code = '';

    for (let cursor = 0; cursor < randomBytes.length; cursor++) {
      code += RECOVERY_CODE_ALPHABET[randomBytes[cursor] % RECOVERY_CODE_ALPHABET.length];
    }

    const groupedCode = code.match(new RegExp(`.{1,${segmentLength}}`, 'g')) || [code];
    codes.push(groupedCode.join(separator));
  }

  return codes;
}

export function hashRecoveryCode(
  code: string,
  options: RecoveryCodeHashOptions = {}
): string {
  const normalizedCode = normalizeRecoveryCode(code);

  if (!normalizedCode) {
    throw new Error('Recovery code must be provided');
  }

  const {
    salt = Buffer.from(getRandomBytes(16)).toString('hex'),
    keyLength = 64,
    cost = 16384,
    blockSize = 8,
    parallelization = 1,
  } = options;

  assertPositiveInteger('keyLength', keyLength);
  assertPositiveInteger('cost', cost);
  assertPositiveInteger('blockSize', blockSize);
  assertPositiveInteger('parallelization', parallelization);

  const crypto = getNodeCrypto();
  const derivedKey = crypto.scryptSync(normalizedCode, salt, keyLength, {
    N: cost,
    r: blockSize,
    p: parallelization,
  });

  return [
    RECOVERY_CODE_HASH_PREFIX,
    cost,
    blockSize,
    parallelization,
    salt,
    derivedKey.toString('hex'),
  ].join('$');
}

export function verifyRecoveryCode(code: string, hash: string): boolean {
  const normalizedCode = normalizeRecoveryCode(code);

  if (!normalizedCode || !hash) {
    return false;
  }

  const [prefix, cost, blockSize, parallelization, salt, expectedHash] = hash.split('$');

  if (
    prefix !== RECOVERY_CODE_HASH_PREFIX ||
    !cost ||
    !blockSize ||
    !parallelization ||
    !salt ||
    !expectedHash
  ) {
    return false;
  }

  const crypto = getNodeCrypto();
  const actualHash = crypto.scryptSync(normalizedCode, salt, expectedHash.length / 2, {
    N: Number(cost),
    r: Number(blockSize),
    p: Number(parallelization),
  }).toString('hex');

  return constantTimeEqual(actualHash, expectedHash);
}

export function createRecoveryCodeSet(
  options: RecoveryCodeOptions = {},
  hashOptions: RecoveryCodeHashOptions = {}
): RecoveryCodeSet {
  const codes = generateRecoveryCodes(options);

  return {
    codes,
    hashes: codes.map((code) => hashRecoveryCode(code, hashOptions)),
  };
}

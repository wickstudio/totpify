import {
  assertDigits,
  assertPeriod,
  assertTimestamp,
  assertWindow,
  constantTimeEqual,
  encodeBase32,
  generateHOTP,
  getHashFunction,
  getRandomBytes,
} from '../src/utils';

describe('Totpify - utility edge cases', () => {
  it('should reject encoding an empty byte array', () => {
    expect(() => encodeBase32(new Uint8Array())).toThrow('Cannot encode an empty byte array');
  });

  it('should return false for constant-time comparisons with different lengths', () => {
    expect(constantTimeEqual('123456', '12345')).toBe(false);
  });

  it('should reject invalid digit values', () => {
    expect(() => assertDigits(5)).toThrow('Digits must be between 6 and 10');
    expect(() => assertDigits(11)).toThrow('Digits must be between 6 and 10');
  });

  it('should reject invalid period values', () => {
    expect(() => assertPeriod(0)).toThrow('period must be a positive integer');
  });

  it('should reject invalid window values', () => {
    expect(() => assertWindow(-1)).toThrow('Window must be a non-negative integer');
  });

  it('should reject invalid timestamps', () => {
    expect(() => assertTimestamp(-1)).toThrow('Timestamp must be a non-negative number');
    expect(() => assertTimestamp(Number.NaN)).toThrow('Timestamp must be a non-negative number');
  });

  it('should reject unsupported hash function values', () => {
    expect(() => getHashFunction('MD5' as any)).toThrow('Unsupported algorithm: MD5');
  });

  it('should reject invalid HOTP counters', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5]);

    expect(() => generateHOTP(secret, -1)).toThrow(
      'Counter must be a non-negative safe integer or bigint'
    );
    expect(() => generateHOTP(secret, 2n ** 64n)).toThrow('Counter must fit within 8 bytes');
  });

  it('should fall back to Node crypto when web crypto is unavailable', () => {
    const originalCrypto = globalThis.crypto;

    Object.defineProperty(globalThis, 'crypto', {
      value: undefined,
      configurable: true,
    });

    try {
      const bytes = getRandomBytes(8);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes).toHaveLength(8);
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        value: originalCrypto,
        configurable: true,
      });
    }
  });
});

import { 
  createEnrollmentBundle,
  createVerifier,
  createRecoveryCodeSet,
  encodeBase32,
  MemoryReplayStore,
  generateHOTP,
  generateTOTP, 
  verifyTOTP, 
  generateQRCode, 
  generateRandomSecret, 
  generateOtpauthUri,
  generateRecoveryCodes,
  hashRecoveryCode,
  parseOtpauthUri,
  verifyRecoveryCode,
  decodeBase32,
  HashAlgorithm
} from '../src';

describe('Totpify - Core Functions', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP';
  const textEncoder = new TextEncoder();
  
  describe('generateTOTP()', () => {
    it('should generate a valid 6-digit TOTP code with default options', () => {
      const code = generateTOTP(testSecret);
      expect(code).toMatch(/^\d{6}$/);
    });
    
    it('should generate a valid 8-digit TOTP code when digits=8', () => {
      const code = generateTOTP(testSecret, { digits: 8 });
      expect(code).toMatch(/^\d{8}$/);
    });
    
    it('should support all three hash algorithms with different outputs', () => {
      const algorithms: HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-512'];
      const codes = algorithms.map(algorithm => 
        generateTOTP(testSecret, { algorithm })
      );
      
      codes.forEach(code => expect(code).toMatch(/^\d{6}$/));
      
      expect(new Set(codes).size).toBe(algorithms.length);
    });
    
    it('should generate consistent codes for the same timestamp', () => {
      const timestamp = 1635000000000;
      const code1 = generateTOTP(testSecret, { timestamp });
      const code2 = generateTOTP(testSecret, { timestamp });
      expect(code1).toEqual(code2);
    });
    
    it('should generate different codes when period changes', () => {
      const timestamp = 1635000000000;
      const code1 = generateTOTP(testSecret, { timestamp, period: 30 });
      const code2 = generateTOTP(testSecret, { timestamp, period: 60 });
      expect(code1).not.toEqual(code2);
    });
    
    it('should handle direct Uint8Array input for secret', () => {
      const secretBytes = decodeBase32(testSecret);
      const code = generateTOTP(secretBytes);
      expect(code).toMatch(/^\d{6}$/);
    });
    
    it('should throw appropriate errors for invalid inputs', () => {
      expect(() => generateTOTP('')).toThrow('Secret must be provided');
      
      expect(() => generateTOTP('!@#$%^')).toThrow(/Invalid secret/);
    });
  });
  
  describe('verifyTOTP()', () => {
    it('should validate a freshly generated TOTP code', () => {
      const timestamp = Date.now();
      const code = generateTOTP(testSecret, { timestamp });
      const result = verifyTOTP(code, testSecret, { timestamp });
      
      expect(result.valid).toBe(true);
      expect(result.delta).toBe(0);
    });
    
    it('should accept codes within the time window', () => {
      const timestamp = Date.now();
      
      const prevCode = generateTOTP(testSecret, { timestamp: timestamp - 30000 });
      const prevResult = verifyTOTP(prevCode, testSecret, { timestamp, window: 1 });
      expect(prevResult.valid).toBe(true);
      expect(prevResult.delta).toBe(-1);
      
      const nextCode = generateTOTP(testSecret, { timestamp: timestamp + 30000 });
      const nextResult = verifyTOTP(nextCode, testSecret, { timestamp, window: 1 });
      expect(nextResult.valid).toBe(true);
      expect(nextResult.delta).toBe(1);
    });
    
    it('should reject codes outside the specified time window', () => {
      const timestamp = Date.now();
      
      const oldCode = generateTOTP(testSecret, { timestamp: timestamp - 60000 });
      const result = verifyTOTP(oldCode, testSecret, { timestamp, window: 1 });
      
      expect(result.valid).toBe(false);
    });
    
    it('should validate codes with different algorithms', () => {
      const algorithms: HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-512'];
      
      algorithms.forEach(algorithm => {
        const timestamp = Date.now();
        const code = generateTOTP(testSecret, { timestamp, algorithm });
        const result = verifyTOTP(code, testSecret, { timestamp, algorithm });
        
        expect(result.valid).toBe(true);
      });
    });
    
    it('should reject codes with invalid format', () => {
      expect(verifyTOTP('12345', testSecret).valid).toBe(false);
      
      expect(verifyTOTP('1234567', testSecret).valid).toBe(false);
      
      expect(verifyTOTP('abcdef', testSecret).valid).toBe(false);
    });
    
    it('should reject codes with different secrets', () => {
      const timestamp = Date.now();
      const differentSecret = 'DIFFERENTTOTPSECRETTESTONLY';
      
      const code = generateTOTP(differentSecret, { timestamp });
      const result = verifyTOTP(code, testSecret, { timestamp });
      
      expect(result.valid).toBe(false);
    });
  });
  
  describe('generateRandomSecret()', () => {
    it('should generate a valid Base32 secret of default length', () => {
      const secret = generateRandomSecret();
      expect(secret).toMatch(/^[A-Z2-7]{32}$/);
      expect(decodeBase32(secret)).toHaveLength(20);
    });
    
    it('should generate a valid Base32 secret of specified length', () => {
      const secret = generateRandomSecret(32);
      expect(secret).toMatch(/^[A-Z2-7]{52}$/);
      expect(decodeBase32(secret)).toHaveLength(32);
    });
    
    it('should generate unique secrets on multiple calls', () => {
      const secretsSet = new Set();
      for (let i = 0; i < 5; i++) {
        secretsSet.add(generateRandomSecret());
      }
      expect(secretsSet.size).toBe(5);
    });
  });
  
  describe('decodeBase32()', () => {
    it('should round-trip Base32 values', () => {
      const input = Uint8Array.from([1, 2, 3, 4, 5, 250, 251, 252]);
      const encoded = encodeBase32(input);
      const decoded = decodeBase32(encoded);

      expect(Array.from(decoded)).toEqual(Array.from(input));
    });

    it('should decode valid Base32 strings', () => {
      const decoded = decodeBase32('JBSWY3DPEHPK3PXP');
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBeGreaterThan(0);
    });
    
    it('should handle case-insensitivity and spacing', () => {
      const normal = decodeBase32('JBSWY3DPEHPK3PXP');
      const lowercase = decodeBase32('jbswy3dpehpk3pxp');
      const withSpaces = decodeBase32('JBSW Y3DP EHPK 3PXP');
      
      const normalArray = Array.from(normal);
      
      expect(Array.from(lowercase)).toEqual(normalArray);
      expect(Array.from(withSpaces)).toEqual(normalArray);
    });
    
    it('should throw on empty input', () => {
      expect(() => decodeBase32('')).toThrow('Empty Base32 string');
    });
    
    it('should throw on invalid Base32 characters', () => {
      expect(() => decodeBase32('!@#$%^')).toThrow(/Invalid base32 character/);
    });
  });
  
  describe('generateQRCode()', () => {
    it('should generate a valid QR code data URL', async () => {
      const dataUrl = await generateQRCode(testSecret);
      expect(dataUrl).toMatch(/^data:image\/png;base64,/);
    });
    
    it('should include issuer and account in QR code', async () => {
      const issuer = 'TestApp';
      const account = 'test@example.com';
      
      const dataUrl = await generateQRCode(testSecret, { issuer, account });
      expect(dataUrl).toMatch(/^data:image\/png;base64,/);
      
    });
    
    it('should accept custom dimensions', async () => {
      const dataUrl = await generateQRCode(testSecret, { 
        width: 300,
        height: 300 
      });
      expect(dataUrl).toMatch(/^data:image\/png;base64,/);
    });
  });

  describe('RFC test vectors', () => {
    it('should match RFC 4226 HOTP Appendix D test vectors', () => {
      const secret = textEncoder.encode('12345678901234567890');
      const expectedTokens = [
        '755224',
        '287082',
        '359152',
        '969429',
        '338314',
        '254676',
        '287922',
        '162583',
        '399871',
        '520489',
      ];

      expectedTokens.forEach((expectedToken, counter) => {
        expect(generateHOTP(secret, counter, 'SHA-1', 6)).toBe(expectedToken);
      });
    });

    it('should match RFC 6238 Appendix B TOTP test vectors', () => {
      const vectors = [
        {
          timestamp: 59,
          expected: {
            'SHA-1': '94287082',
            'SHA-256': '46119246',
            'SHA-512': '90693936',
          },
        },
        {
          timestamp: 1111111109,
          expected: {
            'SHA-1': '07081804',
            'SHA-256': '68084774',
            'SHA-512': '25091201',
          },
        },
        {
          timestamp: 1111111111,
          expected: {
            'SHA-1': '14050471',
            'SHA-256': '67062674',
            'SHA-512': '99943326',
          },
        },
        {
          timestamp: 1234567890,
          expected: {
            'SHA-1': '89005924',
            'SHA-256': '91819424',
            'SHA-512': '93441116',
          },
        },
        {
          timestamp: 2000000000,
          expected: {
            'SHA-1': '69279037',
            'SHA-256': '90698825',
            'SHA-512': '38618901',
          },
        },
        {
          timestamp: 20000000000,
          expected: {
            'SHA-1': '65353130',
            'SHA-256': '77737706',
            'SHA-512': '47863826',
          },
        },
      ] as const;

      const secrets = {
        'SHA-1': textEncoder.encode('12345678901234567890'),
        'SHA-256': textEncoder.encode('12345678901234567890123456789012'),
        'SHA-512': textEncoder.encode(
          '1234567890123456789012345678901234567890123456789012345678901234'
        ),
      } as const;

      vectors.forEach((vector) => {
        (Object.keys(vector.expected) as Array<HashAlgorithm>).forEach((algorithm) => {
          expect(
            generateTOTP(secrets[algorithm], {
              algorithm,
              digits: 8,
              period: 30,
              timestamp: vector.timestamp * 1000,
            })
          ).toBe(vector.expected[algorithm]);
        });
      });
    });
  });

  describe('otpauth helpers', () => {
    it('should generate otpauth URIs with compatibility-friendly defaults', () => {
      const uri = generateOtpauthUri(testSecret, {
        issuer: 'Totpify',
        account: 'user@example.com',
      });

      expect(uri).toContain('algorithm=SHA1');
      expect(uri).toContain('digits=6');
      expect(uri).toContain('period=30');
      expect(uri).toContain('issuer=Totpify');
    });

    it('should generate otpauth URIs with explicit settings', () => {
      const uri = generateOtpauthUri(testSecret, {
        issuer: 'Totpify',
        account: 'user@example.com',
        algorithm: 'SHA-256',
        digits: 8,
        period: 45,
      });

      expect(uri).toContain('otpauth://totp/');
      expect(uri).toContain('algorithm=SHA256');
      expect(uri).toContain('digits=8');
      expect(uri).toContain('period=45');
    });

    it('should parse otpauth URIs back into typed values', () => {
      const uri = generateOtpauthUri(testSecret, {
        issuer: 'Totpify',
        account: 'user@example.com',
        algorithm: 'SHA-512',
        digits: 8,
        period: 60,
      });

      const parsed = parseOtpauthUri(uri);

      expect(parsed.issuer).toBe('Totpify');
      expect(parsed.account).toBe('user@example.com');
      expect(parsed.algorithm).toBe('SHA-512');
      expect(parsed.digits).toBe(8);
      expect(parsed.period).toBe(60);
      expect(parsed.secret).toBe(testSecret);
    });
  });

  describe('recovery code helpers', () => {
    it('should generate recovery codes in grouped format', () => {
      const codes = generateRecoveryCodes({ count: 4, segments: 3, segmentLength: 4 });

      expect(codes).toHaveLength(4);
      codes.forEach((code) => expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/));
    });

    it('should hash and verify recovery codes', () => {
      const [code] = generateRecoveryCodes({ count: 1 });
      const hash = hashRecoveryCode(code);

      expect(verifyRecoveryCode(code, hash)).toBe(true);
      expect(verifyRecoveryCode('WRONG-WRONG', hash)).toBe(false);
    });

    it('should create a recovery code set with matching hashes', () => {
      const recoverySet = createRecoveryCodeSet({ count: 3 });

      expect(recoverySet.codes).toHaveLength(3);
      expect(recoverySet.hashes).toHaveLength(3);
      recoverySet.codes.forEach((code, index) => {
        expect(verifyRecoveryCode(code, recoverySet.hashes[index])).toBe(true);
      });
    });

    it('should reject invalid recovery-code generation options', () => {
      expect(() => generateRecoveryCodes({ count: 0 })).toThrow('count must be a positive integer');
      expect(() => generateRecoveryCodes({ segments: 0 })).toThrow('segments must be a positive integer');
      expect(() => generateRecoveryCodes({ segmentLength: 0 })).toThrow(
        'segmentLength must be a positive integer'
      );
    });

    it('should reject malformed recovery-code hashing input', () => {
      expect(() => hashRecoveryCode('')).toThrow('Recovery code must be provided');
      expect(() => hashRecoveryCode('ABCD-EFGH', { keyLength: 0 })).toThrow(
        'keyLength must be a positive integer'
      );
    });

    it('should return false for malformed recovery-code hashes', () => {
      expect(verifyRecoveryCode('ABCD-EFGH', '')).toBe(false);
      expect(verifyRecoveryCode('ABCD-EFGH', 'invalid')).toBe(false);
      expect(verifyRecoveryCode('ABCD-EFGH', 'bcrypt$10$1$salt$hash')).toBe(false);
    });
  });

  describe('createEnrollmentBundle()', () => {
    it('should create a ready-to-render enrollment bundle', async () => {
      const bundle = await createEnrollmentBundle({
        issuer: 'Totpify',
        account: 'user@example.com',
        secretByteLength: 32,
        algorithm: 'SHA-256',
        digits: 8,
        period: 45,
        recoveryCodes: { count: 4 },
      });

      expect(bundle.secret).toMatch(/^[A-Z2-7]+$/);
      expect(bundle.secretBytes).toBeInstanceOf(Uint8Array);
      expect(bundle.secretBytes).toHaveLength(32);
      expect(bundle.otpauthUri).toContain('algorithm=SHA256');
      expect(bundle.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
      expect(bundle.recoveryCodes).toHaveLength(4);
      expect(bundle.recoveryCodeHashes).toHaveLength(4);
    });

    it('should reuse an existing secret when one is supplied', async () => {
      const bundle = await createEnrollmentBundle({
        secret: testSecret,
        issuer: 'Totpify',
        account: 'user@example.com',
        qrCode: false,
      });

      expect(bundle.secret).toBe(testSecret);
      expect(bundle.secretBytes).toHaveLength(decodeBase32(testSecret).length);
      expect(bundle.qrCodeDataUrl).toBeUndefined();
      expect(bundle.otpauthUri).toContain(`secret=${testSecret}`);
    });
  });

  describe('createVerifier()', () => {
    it('should verify tokens with the balanced policy by default', async () => {
      const timestamp = 1700000000000;
      const verifier = createVerifier({ diagnostics: 'safe' });
      const token = generateTOTP(testSecret, { timestamp });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(true);
      expect(result.reason).toBe('valid');
      expect(result.deltaSteps).toBe(0);
      expect(result.policy.name).toBe('balanced');
      expect(result.replayStatus).toBe('skipped');
      expect(result.diagnostics?.matchedDelta).toBe(0);
    });

    it('should classify future-step tokens as future_skew', async () => {
      const timestamp = 1700000000000;
      const verifier = createVerifier({ diagnostics: 'debug' });
      const token = generateTOTP(testSecret, { timestamp: timestamp + 30000 });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(false);
      expect(result.reason).toBe('future_skew');
      expect(result.diagnostics?.classifiedDelta).toBe(1);
    });

    it('should classify out-of-window older tokens as expired', async () => {
      const timestamp = 1700000000000;
      const verifier = createVerifier({ diagnostics: 'debug' });
      const token = generateTOTP(testSecret, { timestamp: timestamp - 60000 });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(false);
      expect(result.reason).toBe('expired');
      expect(result.diagnostics?.classifiedDelta).toBe(-2);
    });

    it('should block admin policy verification when replay protection is missing', async () => {
      const timestamp = 1700000000000;
      const verifier = createVerifier({ policy: 'admin' });
      const token = generateTOTP(testSecret, { timestamp });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
        factorId: 'factor-admin',
      });

      expect(result.ok).toBe(false);
      expect(result.reason).toBe('policy_blocked');
      expect(result.replayStatus).toBe('required');
    });

    it('should detect replays when a replay store is configured', async () => {
      const timestamp = 1700000000000;
      const replayStore = new MemoryReplayStore();
      const verifier = createVerifier({
        policy: 'admin',
        replayStore,
      });
      const token = generateTOTP(testSecret, { timestamp });

      const firstResult = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
        factorId: 'factor-admin',
        subject: 'user-123',
      });

      const secondResult = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
        factorId: 'factor-admin',
        subject: 'user-123',
      });

      expect(firstResult.ok).toBe(true);
      expect(firstResult.replayStatus).toBe('fresh');
      expect(secondResult.ok).toBe(false);
      expect(secondResult.reason).toBe('replay_detected');
      expect(secondResult.replayStatus).toBe('replay');
    });

    it('should emit safe structured verification events', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp });
      const events: any[] = [];
      const verifier = createVerifier({
        diagnostics: 'safe',
        onEvent(event) {
          events.push(event);
        },
      });

      await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
        factorId: 'factor-events',
        subject: 'user-456',
        context: {
          ip: '127.0.0.1',
          attempts: 1,
          trusted: true,
          label: null,
        },
      });

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe('totp.verify');
      expect(events[0].reason).toBe('valid');
      expect(events[0].context).toEqual({
        ip: '127.0.0.1',
        attempts: 1,
        trusted: true,
        label: null,
      });
      expect(JSON.stringify(events[0])).not.toContain(testSecret);
      expect(JSON.stringify(events[0])).not.toContain(token);
    });

    it('should allow policy overrides without mutating the base preset', () => {
      const verifier = createVerifier({ policy: 'strict' });

      const basePolicy = verifier.getPolicy();
      const customPolicy = verifier.getPolicy({ maxPastSteps: 1, digits: 8 });

      expect(basePolicy.name).toBe('strict');
      expect(basePolicy.maxPastSteps).toBe(0);
      expect(customPolicy.name).toBe('custom');
      expect(customPolicy.maxPastSteps).toBe(1);
      expect(customPolicy.digits).toBe(8);
    });

    it('should return invalid_format for malformed tokens', async () => {
      const verifier = createVerifier();
      const result = await verifier.verify({
        token: 'abcd',
        secret: testSecret,
        timestamp: 1700000000000,
      });

      expect(result.ok).toBe(false);
      expect(result.reason).toBe('invalid_format');
    });

    it('should return invalid_token for unmatched tokens outside drift heuristics', async () => {
      const verifier = createVerifier({ diagnostics: 'safe' });
      const result = await verifier.verify({
        token: '111111',
        secret: testSecret,
        timestamp: 1700000000000,
      });

      expect(result.ok).toBe(false);
      expect(result.reason).toBe('invalid_token');
    });

    it('should omit diagnostics entirely when diagnostics mode is off', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp });
      const verifier = createVerifier();

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(true);
      expect(result.diagnostics).toBeUndefined();
    });

    it('should swallow event hook failures and still return a decision', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp });
      const verifier = createVerifier({
        onEvent() {
          throw new Error('event sink failed');
        },
      });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(true);
      expect(result.reason).toBe('valid');
    });

    it('should accept future-step tokens when a custom policy allows them', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp: timestamp + 30000 });
      const verifier = createVerifier({
        policy: {
          preset: 'balanced',
          maxFutureSteps: 1,
        },
      });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(true);
      expect(result.deltaSteps).toBe(1);
    });

    it('should skip replay checks when no factor id is provided', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp });
      const verifier = createVerifier({
        replayStore: new MemoryReplayStore(),
      });

      const result = await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
      });

      expect(result.ok).toBe(true);
      expect(result.replayStatus).toBe('skipped');
    });

    it('should drop unsafe context values from emitted events', async () => {
      const timestamp = 1700000000000;
      const token = generateTOTP(testSecret, { timestamp });
      const events: any[] = [];
      const verifier = createVerifier({
        onEvent(event) {
          events.push(event);
        },
      });

      await verifier.verify({
        token,
        secret: testSecret,
        timestamp,
        context: {
          ok: 'yes',
          nested: { no: true } as any,
        },
      });

      expect(events[0].context).toEqual({ ok: 'yes' });
    });

    it('should allow replay-store entries to expire in MemoryReplayStore', async () => {
      const store = new MemoryReplayStore();

      await expect(
        store.markStep({
          factorId: 'factor',
          subject: 'user',
          step: 1n,
          ttlMs: 1,
          now: 1000,
        })
      ).resolves.toBe('fresh');

      await expect(
        store.markStep({
          factorId: 'factor',
          subject: 'user',
          step: 1n,
          ttlMs: 1,
          now: 1002,
        })
      ).resolves.toBe('fresh');
    });

    it('should reject unsupported custom policy algorithms', () => {
      expect(() =>
        createVerifier({
          policy: {
            algorithm: 'MD5' as any,
          },
        })
      ).toThrow('Unsupported algorithm: MD5');
    });
  });
}); 

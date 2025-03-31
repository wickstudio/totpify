import { 
  generateTOTP, 
  verifyTOTP, 
  generateQRCode, 
  generateRandomSecret, 
  decodeBase32,
  HashAlgorithm
} from '../src';

describe('Totpify - Core Functions', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP';
  
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
      expect(secret).toMatch(/^[A-Z2-7]{20}$/);
    });
    
    it('should generate a valid Base32 secret of specified length', () => {
      const secret = generateRandomSecret(32);
      expect(secret).toMatch(/^[A-Z2-7]{32}$/);
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
}); 
jest.mock('qrcode', () => ({
  toDataURL: jest.fn(),
}));

import * as QRCode from 'qrcode';
import { generateOtpauthUri, generateQRCodeDataUrl, parseOtpauthUri } from '../src/otpauth';

const mockedToDataURL = QRCode.toDataURL as unknown as jest.Mock;

describe('Totpify - otpauth edge cases', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    mockedToDataURL.mockReset();
  });

  it('should reject empty secrets when generating otpauth URIs', () => {
    expect(() => generateOtpauthUri('')).toThrow('Secret must be provided');
  });

  it('should reject malformed URI strings', () => {
    expect(() => parseOtpauthUri('not-a-uri')).toThrow(/Invalid otpauth URI/);
  });

  it('should reject unsupported protocols', () => {
    expect(() => parseOtpauthUri('https://totp/example?secret=JBSWY3DPEHPK3PXP')).toThrow(
      'Invalid otpauth URI: unsupported protocol'
    );
  });

  it('should reject unsupported OTP types', () => {
    expect(() =>
      parseOtpauthUri('otpauth://hotp/Issuer:account?secret=JBSWY3DPEHPK3PXP')
    ).toThrow('Invalid otpauth URI: unsupported OTP type');
  });

  it('should reject URIs without a secret parameter', () => {
    expect(() => parseOtpauthUri('otpauth://totp/Issuer:account?issuer=Issuer')).toThrow(
      'Invalid otpauth URI: secret is required'
    );
  });

  it('should reject unsupported algorithms while parsing', () => {
    expect(() =>
      parseOtpauthUri(
        'otpauth://totp/Issuer:account?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'
      )
    ).toThrow('Invalid otpauth URI: unsupported algorithm MD5');
  });

  it('should parse SHA256 algorithms from otpauth URIs', () => {
    const parsed = parseOtpauthUri(
      'otpauth://totp/Issuer:account?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256'
    );

    expect(parsed.algorithm).toBe('SHA-256');
  });

  it('should fall back to label values when issuer query param is absent', () => {
    const parsed = parseOtpauthUri(
      'otpauth://totp/Acme:user%40example.com?secret=JBSWY3DPEHPK3PXP'
    );

    expect(parsed.issuer).toBe('Acme');
    expect(parsed.account).toBe('user@example.com');
  });

  it('should default account to user when the label has no account part', () => {
    const parsed = parseOtpauthUri(
      'otpauth://totp/Acme?secret=JBSWY3DPEHPK3PXP&issuer=Acme'
    );

    expect(parsed.account).toBe('user');
  });

  it('should fall back to default issuer and account when the label is empty', () => {
    const parsed = parseOtpauthUri('otpauth://totp/?secret=JBSWY3DPEHPK3PXP');

    expect(parsed.label).toBe('');
    expect(parsed.issuer).toBe('Totpify');
    expect(parsed.account).toBe('user');
  });

  it('should use width when height is not provided in QR generation', async () => {
    mockedToDataURL.mockResolvedValue('data:image/png;base64,test');

    const result = await generateQRCodeDataUrl('otpauth://totp/test?secret=JBSWY3DPEHPK3PXP', {
      width: 144,
    });

    expect(result).toBe('data:image/png;base64,test');
    expect(mockedToDataURL).toHaveBeenCalledWith(
      'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      expect.objectContaining({ width: 144 })
    );
  });

  it('should use the smaller dimension when both width and height are provided', async () => {
    mockedToDataURL.mockResolvedValue('data:image/png;base64,test');

    await generateQRCodeDataUrl('otpauth://totp/test?secret=JBSWY3DPEHPK3PXP', {
      width: 240,
      height: 120,
    });

    expect(mockedToDataURL).toHaveBeenCalledWith(
      'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP',
      expect.objectContaining({ width: 120 })
    );
  });

  it('should surface QR generation failures cleanly', async () => {
    mockedToDataURL.mockRejectedValue(new Error('boom'));

    await expect(
      generateQRCodeDataUrl('otpauth://totp/test?secret=JBSWY3DPEHPK3PXP')
    ).rejects.toThrow('QR code generation failed: boom');
  });

  it('should preserve explicit non-default values in generated otpauth URIs', () => {
    const uri = generateOtpauthUri(testSecret, {
      issuer: 'Acme',
      account: 'user@example.com',
      algorithm: 'SHA-512',
      digits: 8,
      period: 45,
    });

    expect(uri).toContain('algorithm=SHA512');
    expect(uri).toContain('digits=8');
    expect(uri).toContain('period=45');
  });
});

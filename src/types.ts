export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface TOTPOptions {
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
  timestamp?: number;
  window?: number;
}

export interface QRCodeOptions {
  issuer?: string;
  account?: string;
  width?: number;
  height?: number;
}

export type VerifyResult = {
  valid: boolean;
  delta?: number;
}; 
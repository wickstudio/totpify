import { exec } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { promisify } from 'util';

const execAsync = promisify(exec);
const cliPath = path.resolve(__dirname, '../src/cli.ts');

describe('Totpify - CLI Interface', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP';
  
  const runCLI = async (args: string): Promise<{stdout: string, stderr: string}> => {
    try {
      return await execAsync(`ts-node ${cliPath} ${args}`);
    } catch (error) {
      return error as any;
    }
  };

  describe('Help and Basic Commands', () => {
    it('should display help information when help command is used', async () => {
      const { stdout } = await runCLI('help');
      expect(stdout).toContain('Totpify - Advanced TOTP Generator and Verifier');
      expect(stdout).toContain('Usage:');
      expect(stdout).toContain('Options:');
      expect(stdout).toContain('Examples:');
    });
    
    it('should display help when no command is provided', async () => {
      const { stdout } = await runCLI('');
      expect(stdout).toContain('Totpify - Advanced TOTP Generator and Verifier');
    });
    
    it('should display help with --help flag', async () => {
      const { stdout } = await runCLI('--help');
      expect(stdout).toContain('Totpify - Advanced TOTP Generator and Verifier');
    });
  });

  describe('TOTP Code Generation', () => {
    it('should generate a 6-digit TOTP code with default options', async () => {
      const { stdout } = await runCLI(`generate ${testSecret}`);
      expect(stdout.trim()).toMatch(/^\d{6}$/);
    });
    
    it('should generate an 8-digit TOTP code with custom digits option', async () => {
      const { stdout } = await runCLI(`generate ${testSecret} --digits=8`);
      expect(stdout.trim()).toMatch(/^\d{8}$/);
    });
    
    it('should support different hash algorithms', async () => {
      const sha1Result = await runCLI(`generate ${testSecret} --algorithm=SHA-1`);
      const sha256Result = await runCLI(`generate ${testSecret} --algorithm=SHA-256`);
      const sha512Result = await runCLI(`generate ${testSecret} --algorithm=SHA-512`);
      
      expect(sha1Result.stdout.trim()).toMatch(/^\d{6}$/);
      expect(sha256Result.stdout.trim()).toMatch(/^\d{6}$/);
      expect(sha512Result.stdout.trim()).toMatch(/^\d{6}$/);
      
      const codes = [
        sha1Result.stdout.trim(), 
        sha256Result.stdout.trim(), 
        sha512Result.stdout.trim()
      ];
      expect(new Set(codes).size).toBe(3);
    }, 15000);
    
    it('should respond with error for invalid secret', async () => {
      const result = await runCLI('generate INVALID!@#');
      expect(result.stderr).toBeTruthy();
      expect(result.stderr).toContain('Error:');
    });
    
    it('should error when no secret is provided', async () => {
      const result = await runCLI('generate');
      expect(result.stderr).toBeTruthy();
      expect(result.stderr).toContain('Secret is required');
    });
  });

  describe('Secret Generation', () => {
    it('should create a valid Base32 secret with default length', async () => {
      const { stdout } = await runCLI('create-secret');
      expect(stdout.trim()).toMatch(/^[A-Z2-7]{20}$/);
    });
    
    it('should create a valid Base32 secret with custom length', async () => {
      const { stdout } = await runCLI('create-secret 32');
      expect(stdout.trim()).toMatch(/^[A-Z2-7]{32}$/);
    });
    
    it('should error on invalid length parameter', async () => {
      const result = await runCLI('create-secret -5');
      expect(result.stderr).toBeTruthy();
      expect(result.stderr).toContain('Length must be a positive number');
    });
  });

  describe('TOTP Verification', () => {
    it('should verify a valid freshly generated code', async () => {
      const { stdout: code } = await runCLI(`generate ${testSecret}`);
      
      const { stdout: verificationResult } = await runCLI(`verify ${code.trim()} ${testSecret}`);
      expect(verificationResult).toContain('Valid');
    }, 10000);
    
    it('should reject an invalid TOTP code', async () => {
      const result = await runCLI(`verify 000000 ${testSecret}`);
      
      expect(result.stdout).toContain('Invalid code');
    }, 10000);
    
    it('should error when code and secret are not provided', async () => {
      const noArgsResult = await runCLI('verify');
      expect(noArgsResult.stderr).toContain('Code and secret are required');
      
      const noSecretResult = await runCLI('verify 123456');
      expect(noSecretResult.stderr).toContain('Code and secret are required');
    }, 10000);
  });

  describe('QR Code Generation', () => {
    const tempQrFile = path.join(__dirname, 'test-qr.png');
    
    beforeAll(() => {
      if (fs.existsSync(tempQrFile)) {
        fs.unlinkSync(tempQrFile);
      }
    });
    
    afterAll(() => {
      if (fs.existsSync(tempQrFile)) {
        fs.unlinkSync(tempQrFile);
      }
    });
    
    it('should generate a QR code data URL', async () => {
      const { stdout } = await runCLI(`qrcode ${testSecret}`);
      expect(stdout.trim()).toMatch(/^data:image\/png;base64,/);
    });
    
    it('should save QR code to a file when path is provided', async () => {
      const { stdout } = await runCLI(`qrcode ${testSecret} ${tempQrFile}`);
      
      expect(stdout).toContain(`QR code saved to ${tempQrFile}`);
      
      expect(fs.existsSync(tempQrFile)).toBe(true);
      const fileStats = fs.statSync(tempQrFile);
      expect(fileStats.size).toBeGreaterThan(0);
    });
    
    it('should support custom issuer and account parameters', async () => {
      const { stdout } = await runCLI(
        `qrcode ${testSecret} --issuer=TestApp --account=user@example.com`
      );
      expect(stdout.trim()).toMatch(/^data:image\/png;base64,/);
    });
    
    it('should error when no secret is provided', async () => {
      const result = await runCLI('qrcode');
      expect(result.stderr).toContain('Secret is required');
    });
  });
  
  describe('Error Handling', () => {
    it('should report error for unknown commands', async () => {
      const result = await runCLI('unknown-command');
      expect(result.stderr).toContain('Unknown command');
    });
    
    it('should validate algorithm parameter', async () => {
      const result = await runCLI(`generate ${testSecret} --algorithm=INVALID`);
      expect(result.stderr).toContain('Invalid algorithm');
    });
    
    it('should validate digits parameter', async () => {
      const result = await runCLI(`generate ${testSecret} --digits=9`);
      expect(result.stderr).toContain('Digits must be 6 or 8');
    });
    
    it('should validate period parameter', async () => {
      const result = await runCLI(`generate ${testSecret} --period=-30`);
      expect(result.stderr).toContain('Invalid period');
    });
  });
});
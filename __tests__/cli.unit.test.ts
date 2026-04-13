import * as fs from 'fs';
import * as path from 'path';
import {
  createCliRuntime,
  getNoOptionArgs,
  getUsageText,
  main,
  parseOptions,
  runCli,
} from '../src/cli';
import { generateTOTP } from '../src/totp';

function createRuntime() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const writes: Array<{ filePath: string; data: Buffer }> = [];

  return {
    stdout,
    stderr,
    writes,
    runtime: {
      stdout: (message: string) => stdout.push(message),
      stderr: (message: string) => stderr.push(message),
      writeFile: (filePath: string, data: Buffer) => writes.push({ filePath, data }),
      resolvePath: (filePath: string) => `ABS:${filePath}`,
    },
  };
}

describe('Totpify - CLI Source Interface', () => {
  const testSecret = 'JBSWY3DPEHPK3PXP';

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should expose usage text and help output directly from source', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const usageText = getUsageText();
    const exitCode = await main([], runtime);

    expect(exitCode).toBe(0);
    expect(stdout[0]).toBe(usageText);
    expect(stderr).toEqual([]);
  });

  it('should parse supported CLI options from source', () => {
    const options = parseOptions([
      '--algorithm=SHA-256',
      '--digits=8',
      '--period=45',
      '--window=2',
      '--issuer=Acme',
      '--account=user@example.com',
      '--ignored',
      '--missing-value',
    ]);

    expect(options).toEqual({
      algorithm: 'SHA-256',
      digits: 8,
      period: 45,
      window: 2,
      issuer: 'Acme',
      account: 'user@example.com',
    });
  });

  it('should reject invalid option values at source level', () => {
    expect(() => parseOptions(['--algorithm=BAD'])).toThrow('Invalid algorithm: BAD');
    expect(() => parseOptions(['--digits=5'])).toThrow('Digits must be between 6 and 10');
    expect(() => parseOptions(['--period=0'])).toThrow('Invalid period: must be a positive number');
    expect(() => parseOptions(['--window=-1'])).toThrow('Invalid window: must be a non-negative number');
  });

  it('should separate option args from positional args', () => {
    expect(
      getNoOptionArgs([
        'generate',
        testSecret,
        '--digits=8',
        '--issuer=Acme',
      ])
    ).toEqual(['generate', testSecret]);
  });

  it('should run generate successfully through the source-level CLI', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['generate', testSecret, '--digits=8'], runtime);

    expect(exitCode).toBe(0);
    expect(stdout[0]).toMatch(/^\d{8}$/);
    expect(stderr).toEqual([]);
  });

  it('should surface unexpected generator errors through the source-level CLI', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['generate', 'not-base32'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Error: Invalid secret: Invalid base32 character in key']);
  });

  it('should return a validation error for missing generate secret', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['generate'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Secret is required']);
  });

  it('should verify valid tokens through the source-level CLI', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const token = generateTOTP(testSecret);
    const exitCode = await runCli(['verify', token, testSecret], runtime);

    expect(exitCode).toBe(0);
    expect(stdout).toEqual(['Valid (time drift: 0 periods)']);
    expect(stderr).toEqual([]);
  });

  it('should reject invalid tokens through the source-level CLI', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['verify', '000000', testSecret], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual(['Invalid code']);
    expect(stderr).toEqual([]);
  });

  it('should return a validation error for missing verify arguments', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['verify', '123456'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Code and secret are required']);
  });

  it('should run qrcode and write the output file through the source-level CLI', async () => {
    const { runtime, stdout, stderr, writes } = createRuntime();
    const exitCode = await runCli(
      ['qrcode', testSecret, '--issuer=Acme', '--account=user@example.com', 'setup.png'],
      runtime
    );

    expect(exitCode).toBe(0);
    expect(stdout).toEqual(['QR code saved to setup.png']);
    expect(stderr).toEqual([]);
    expect(writes).toHaveLength(1);
    expect(writes[0].filePath).toBe('ABS:setup.png');
    expect(writes[0].data.length).toBeGreaterThan(0);
  });

  it('should print QR code data URLs when no output file is provided', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['qrcode', testSecret], runtime);

    expect(exitCode).toBe(0);
    expect(stdout[0]).toMatch(/^data:image\/png;base64,/);
    expect(stderr).toEqual([]);
  });

  it('should require a secret for qrcode generation at source level', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['qrcode'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Secret is required']);
  });

  it('should show usage for unknown commands without breaking CLI behavior', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['unknown-command'], runtime);

    expect(exitCode).toBe(1);
    expect(stderr).toEqual(['Unknown command: unknown-command']);
    expect(stdout[0]).toContain('Usage:');
  });

  it('should create secrets with the default byte length at source level', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['create-secret'], runtime);

    expect(exitCode).toBe(0);
    expect(stdout[0]).toMatch(/^[A-Z2-7]+$/);
    expect(stdout[0].length).toBe(32);
    expect(stderr).toEqual([]);
  });

  it('should reject invalid create-secret byte counts at source level', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['create-secret', '0'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Bytes must be a positive number']);
  });

  it('should generate recovery codes at source level', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['recovery-codes', '3'], runtime);

    expect(exitCode).toBe(0);
    expect(stdout[0].split('\n')).toHaveLength(3);
    expect(stderr).toEqual([]);
  });

  it('should return source-level errors for invalid recovery code command input', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['recovery-codes', '0'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Count must be a positive number']);
  });

  it('should surface option parsing errors from source-level command execution', async () => {
    const { runtime, stdout, stderr } = createRuntime();
    const exitCode = await runCli(['generate', testSecret, '--digits=5'], runtime);

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Digits must be between 6 and 10']);
  });

  it('should create the default runtime with console and filesystem bindings', () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const runtime = createCliRuntime();
    const payload = Buffer.from('hello');
    const tempFile = path.join(process.cwd(), 'tmp-cli-runtime-test.txt');

    runtime.stdout('hello');
    runtime.stderr('oops');
    runtime.writeFile(tempFile, payload);

    expect(runtime.resolvePath('demo.txt')).toBe(path.resolve('demo.txt'));
    expect(logSpy).toHaveBeenCalledWith('hello');
    expect(errorSpy).toHaveBeenCalledWith('oops');
    expect(fs.readFileSync(tempFile)).toEqual(payload);

    fs.unlinkSync(tempFile);
  });
});

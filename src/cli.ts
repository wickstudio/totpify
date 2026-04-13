#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { generateTOTP, verifyTOTP, generateQRCode, generateRandomSecret } from './totp';
import { generateRecoveryCodes } from './recovery';
import { HashAlgorithm } from './types';

export interface CliRuntime {
  stdout: (message: string) => void;
  stderr: (message: string) => void;
  writeFile: (filePath: string, data: Buffer) => void;
  resolvePath: (filePath: string) => string;
}

type CliOptions = {
  algorithm?: HashAlgorithm;
  digits?: number;
  period?: number;
  window?: number;
  issuer?: string;
  account?: string;
};

class CliInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CliInputError';
  }
}

export function getUsageText(): string {
  return `
Totpify - Advanced TOTP Generator and Verifier
Usage:
  totpify generate <secret> [options]
  totpify verify <code> <secret> [options]
  totpify qrcode <secret> [options] [output-file]
  totpify create-secret [bytes]
  totpify recovery-codes [count]

Options:
  --algorithm=<alg>    Hash algorithm (SHA-1, SHA-256, SHA-512)
  --digits=<num>       Number of digits (6-10)
  --period=<seconds>   Token validity period in seconds (default: 30)
  --window=<num>       Time drift window (default: 1)
  --issuer=<name>      Issuer name for QR code
  --account=<name>     Account name for QR code

Examples:
  totpify generate JBSWY3DPEHPK3PXP
  totpify verify 123456 JBSWY3DPEHPK3PXP
  totpify qrcode JBSWY3DPEHPK3PXP --issuer=MyApp code.png
  totpify create-secret
  totpify recovery-codes 10
`;
}

export function printUsage(write: (message: string) => void = console.log): void {
  write(getUsageText());
}

export function parseOptions(args: string[]): CliOptions {
  const options: CliOptions = {};

  for (const arg of args) {
    if (!arg.startsWith('--')) {
      continue;
    }

    const [key, value] = arg.substring(2).split('=');

    if (!key || typeof value === 'undefined') {
      continue;
    }

    if (key === 'algorithm') {
      if (['SHA-1', 'SHA-256', 'SHA-512'].includes(value)) {
        options[key] = value as HashAlgorithm;
      } else {
        throw new CliInputError(`Invalid algorithm: ${value}`);
      }
    } else if (key === 'digits') {
      const digits = parseInt(value, 10);

      if (isNaN(digits) || digits < 6 || digits > 10) {
        throw new CliInputError('Digits must be between 6 and 10');
      }

      options[key] = digits;
    } else if (key === 'period') {
      const period = parseInt(value, 10);

      if (isNaN(period) || period <= 0) {
        throw new CliInputError('Invalid period: must be a positive number');
      }

      options[key] = period;
    } else if (key === 'window') {
      const window = parseInt(value, 10);

      if (isNaN(window) || window < 0) {
        throw new CliInputError('Invalid window: must be a non-negative number');
      }

      options[key] = window;
    } else if (key === 'issuer' || key === 'account') {
      options[key] = value;
    }
  }

  return options;
}

export function getNoOptionArgs(args: string[]): string[] {
  return args.filter((arg) => !arg.startsWith('--'));
}

export function createCliRuntime(): CliRuntime {
  return {
    stdout: (message) => console.log(message),
    stderr: (message) => console.error(message),
    writeFile: (filePath, data) => fs.writeFileSync(filePath, data),
    resolvePath: (filePath) => path.resolve(filePath),
  };
}

export async function runCli(
  argv: string[] = process.argv.slice(2),
  runtime: CliRuntime = createCliRuntime()
): Promise<number> {
  const command = argv[0];

  if (!command || command === 'help' || command === '--help') {
    printUsage(runtime.stdout);
    return 0;
  }

  try {
    const noOptionArgs = getNoOptionArgs(argv.slice(1));
    const options = parseOptions(argv.slice(1));

    switch (command) {
      case 'generate': {
        if (!noOptionArgs[0]) {
          runtime.stderr('Secret is required');
          return 1;
        }

        const token = generateTOTP(noOptionArgs[0], options);
        runtime.stdout(token);
        return 0;
      }

      case 'verify': {
        if (!noOptionArgs[0] || !noOptionArgs[1]) {
          runtime.stderr('Code and secret are required');
          return 1;
        }

        const result = verifyTOTP(noOptionArgs[0], noOptionArgs[1], options);

        if (result.valid) {
          runtime.stdout(`Valid (time drift: ${result.delta || 0} periods)`);
          return 0;
        }

        runtime.stdout('Invalid code');
        return 1;
      }

      case 'qrcode': {
        if (!noOptionArgs[0]) {
          runtime.stderr('Secret is required');
          return 1;
        }

        const qrOptions = {
          issuer: options.issuer || 'Totpify',
          account: options.account || 'user',
          algorithm: options.algorithm,
          digits: options.digits,
          period: options.period,
        };
        const dataUrl = await generateQRCode(noOptionArgs[0], qrOptions);
        const outputFile = noOptionArgs[1];

        if (outputFile) {
          const data = dataUrl.split(',')[1];
          const buffer = Buffer.from(data, 'base64');
          runtime.writeFile(runtime.resolvePath(outputFile), buffer);
          runtime.stdout(`QR code saved to ${outputFile}`);
        } else {
          runtime.stdout(dataUrl);
        }

        return 0;
      }

      case 'create-secret': {
        const bytes = noOptionArgs[0] ? parseInt(noOptionArgs[0], 10) : 20;

        if (isNaN(bytes) || bytes <= 0) {
          runtime.stderr('Bytes must be a positive number');
          return 1;
        }

        runtime.stdout(generateRandomSecret(bytes));
        return 0;
      }

      case 'recovery-codes': {
        const count = noOptionArgs[0] ? parseInt(noOptionArgs[0], 10) : 8;

        if (isNaN(count) || count <= 0) {
          runtime.stderr('Count must be a positive number');
          return 1;
        }

        runtime.stdout(generateRecoveryCodes({ count }).join('\n'));
        return 0;
      }

      default:
        runtime.stderr(`Unknown command: ${command}`);
        printUsage(runtime.stdout);
        return 1;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    runtime.stderr(error instanceof CliInputError ? message : `Error: ${message}`);
    return 1;
  }
}

export async function main(
  argv: string[] = process.argv.slice(2),
  runtime: CliRuntime = createCliRuntime()
): Promise<number> {
  return runCli(argv, runtime);
}

if (require.main === module) {
  main()
    .then((exitCode) => {
      process.exit(exitCode);
    })
    .catch((error) => {
      console.error(`Unexpected error: ${error.message}`);
      process.exit(1);
    });
}

import * as fs from 'fs';
import * as path from 'path';
import { generateTOTP, verifyTOTP, generateQRCode, generateRandomSecret } from './totp';
import { HashAlgorithm } from './types';

const args = process.argv.slice(2);
const command = args[0];

function printUsage() {
  console.log(`
Totpify - Advanced TOTP Generator and Verifier
Usage:
  totpify generate <secret> [options]
  totpify verify <code> <secret> [options]
  totpify qrcode <secret> [options] [output-file]
  totpify create-secret [length]

Options:
  --algorithm=<alg>    Hash algorithm (SHA-1, SHA-256, SHA-512)
  --digits=<num>       Number of digits (6, 8)
  --period=<seconds>   Token validity period in seconds (default: 30)
  --window=<num>       Time drift window (default: 1)
  --issuer=<name>      Issuer name for QR code
  --account=<name>     Account name for QR code

Examples:
  totpify generate JBSWY3DPEHPK3PXP
  totpify verify 123456 JBSWY3DPEHPK3PXP
  totpify qrcode JBSWY3DPEHPK3PXP --issuer=MyApp code.png
  totpify create-secret
`);
}

function parseOptions(args: string[]) {
  const options: Record<string, any> = {};
  
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const [key, value] = arg.substring(2).split('=');
      if (key && value) {
        if (key === 'algorithm') {
          if (['SHA-1', 'SHA-256', 'SHA-512'].includes(value)) {
            options[key] = value as HashAlgorithm;
          } else {
            console.error(`Invalid algorithm: ${value}`);
            process.exit(1);
          }
        } else if (key === 'digits') {
          options[key] = parseInt(value, 10);
          if (isNaN(options[key]) || ![6, 8].includes(options[key])) {
            console.error('Digits must be 6 or 8');
            process.exit(1);
          }
        } else if (key === 'period' || key === 'window') {
          options[key] = parseInt(value, 10);
          if (isNaN(options[key]) || options[key] <= 0) {
            console.error(`Invalid ${key}: must be a positive number`);
            process.exit(1);
          }
        } else if (key === 'issuer' || key === 'account') {
          options[key] = value;
        }
      }
    }
  }
  
  return options;
}

function getNoOptionArgs(args: string[]) {
  return args.filter(arg => !arg.startsWith('--'));
}

async function main() {
  if (!command || command === 'help' || command === '--help') {
    printUsage();
    return;
  }
  
  try {
    const noOptionArgs = getNoOptionArgs(args.slice(1));
    const options = parseOptions(args.slice(1));
    
    switch (command) {
      case 'generate': {
        if (!noOptionArgs[0]) {
          console.error('Secret is required');
          process.exit(1);
        }
        
        const token = generateTOTP(noOptionArgs[0], options);
        console.log(token);
        break;
      }
      
      case 'verify': {
        if (!noOptionArgs[0] || !noOptionArgs[1]) {
          console.error('Code and secret are required');
          process.exit(1);
        }
        
        const code = noOptionArgs[0];
        const secret = noOptionArgs[1];
        const result = verifyTOTP(code, secret, options);
        
        if (result.valid) {
          console.log(`Valid (time drift: ${result.delta || 0} periods)`);
          process.exit(0);
        } else {
          console.log('Invalid code');
          process.exit(1);
        }
        break;
      }
      
      case 'qrcode': {
        if (!noOptionArgs[0]) {
          console.error('Secret is required');
          process.exit(1);
        }
        
        const secret = noOptionArgs[0];
        const outputFile = noOptionArgs[1];
        const qrOptions = {
          issuer: options.issuer || 'Totpify',
          account: options.account || 'user',
        };
        
        const dataUrl = await generateQRCode(secret, qrOptions);
        
        if (outputFile) {
          const data = dataUrl.split(',')[1];
          const buffer = Buffer.from(data, 'base64');
          fs.writeFileSync(path.resolve(outputFile), buffer);
          console.log(`QR code saved to ${outputFile}`);
        } else {
          console.log(dataUrl);
        }
        break;
      }
      
      case 'create-secret': {
        const length = noOptionArgs[0] ? parseInt(noOptionArgs[0], 10) : 20;
        if (isNaN(length) || length <= 0) {
          console.error('Length must be a positive number');
          process.exit(1);
        }
        
        const secret = generateRandomSecret(length);
        console.log(secret);
        break;
      }
      
      default:
        console.error(`Unknown command: ${command}`);
        printUsage();
        process.exit(1);
    }
  } catch (error) {
    console.error(`Error: ${(error as Error).message}`);
    process.exit(1);
  }
}

main().catch(error => {
  console.error(`Unexpected error: ${error.message}`);
  process.exit(1);
}); 
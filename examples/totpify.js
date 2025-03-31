/**
 * Totpify - Compatible Live TOTP Generator
 * 
 * This script updates TOTP codes periodically and writes them to a file,
 * then uses a PowerShell command to display the file contents.
 */

const { generateTOTP } = require('../dist');
const fs = require('fs');
const { execSync } = require('child_process');

const secret = process.argv[2] || 'JBSWY3DPEHPK3PXP'; // set your own secret key here
const outputFile = 'totpify-output.txt';

function updateCodes() {
  const now = Date.now();
  const period = 30;
  const currentTimestamp = Math.floor(now / 1000);
  const timeRemaining = period - (currentTimestamp % period);
  
  const sha1Code = generateTOTP(secret, { algorithm: 'SHA-1' });
  const sha256Code = generateTOTP(secret, { algorithm: 'SHA-256' });
  const sha512Code = generateTOTP(secret, { algorithm: 'SHA-512' });
  
  let progressBar = '';
  for (let i = 0; i < 20; i++) {
    progressBar += i < Math.floor((timeRemaining / period) * 20) ? '#' : '-';
  }
  
  let output = '\n';
  output += 'TOTPIFY - Live TOTP Code Generator\n';
  output += '================================\n\n';
  
  output += `Secret: ${secret}\n`;
  output += `Time:   [${progressBar}] ${timeRemaining}s\n\n`;
  
  output += 'Current TOTP Codes:\n';
  output += `  SHA-1:   ${sha1Code} (Standard)\n`;
  output += `  SHA-256: ${sha256Code}\n`;
  output += `  SHA-512: ${sha512Code}\n\n`;
  
  output += 'Options:\n';
  output += `  8-digit code: ${generateTOTP(secret, { digits: 8 })}\n`;
  output += `  60-second period: ${generateTOTP(secret, { period: 60 })}\n\n`;
  
  output += 'Codes will update every second.\n';
  output += 'Press Ctrl+C to exit\n\n';
  
  fs.writeFileSync(outputFile, output, 'utf8');
  
  try {
    execSync(`cls && type ${outputFile}`, { stdio: 'inherit' });
  } catch (err) {
  }
}

console.log('Starting TOTP generator...');

updateCodes();

const intervalId = setInterval(updateCodes, 1000);

process.on('SIGINT', () => {
  clearInterval(intervalId);
  console.log('\nTotpify test completed.\n');
  
  try {
    fs.unlinkSync(outputFile);
  } catch (err) {
  }
  
  process.exit();
});
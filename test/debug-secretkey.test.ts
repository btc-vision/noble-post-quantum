import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

// Helper to log hex of arrays for debugging
function toHex(arr: Uint8Array, len = 64): string {
  return Array.from(arr.slice(0, len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Debug SecretKey Corruption', () => {
  should('check if secretKey is being modified', () => {
    console.log(`\n===== Checking if secretKey gets corrupted =====`);
    const keys = ml_dsa44.keygen();

    // Save original secretKey
    const originalSecretKey = Uint8Array.from(keys.secretKey);
    console.log(`Original SecretKey (first 64 bytes): ${toHex(originalSecretKey)}`);
    console.log(`Original SecretKey (bytes 2000-2064): ${toHex(originalSecretKey.subarray(2000, 2064))}`);
    console.log(`Original SecretKey length: ${originalSecretKey.length}`);

    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    console.log(`\n--- Before Signature #1 ---`);
    console.log(`SecretKey (first 64 bytes): ${toHex(keys.secretKey)}`);
    console.log(`SecretKey (bytes 2000-2064): ${toHex(keys.secretKey.subarray(2000, 2064))}`);

    const sig1 = ml_dsa44.sign(msg, keys.secretKey);
    const isValid1 = ml_dsa44.verify(sig1, msg, keys.publicKey);
    console.log(`\n--- After Signature #1 ---`);
    console.log(`Signature #1 valid: ${isValid1}`);
    console.log(`SecretKey (first 64 bytes): ${toHex(keys.secretKey)}`);
    console.log(`SecretKey (bytes 2000-2064): ${toHex(keys.secretKey.subarray(2000, 2064))}`);
    console.log(`SecretKey modified: ${!arrayEquals(originalSecretKey, keys.secretKey)}`);

    if (!arrayEquals(originalSecretKey, keys.secretKey)) {
      console.log(`\n!!! SECRET KEY WAS MODIFIED AFTER FIRST SIGN !!!`);
      findDifferences(originalSecretKey, keys.secretKey);
    }

    const sig2 = ml_dsa44.sign(msg, keys.secretKey);
    const isValid2 = ml_dsa44.verify(sig2, msg, keys.publicKey);
    console.log(`\n--- After Signature #2 ---`);
    console.log(`Signature #2 valid: ${isValid2}`);
    console.log(`SecretKey (first 64 bytes): ${toHex(keys.secretKey)}`);
    console.log(`SecretKey (bytes 2000-2064): ${toHex(keys.secretKey.subarray(2000, 2064))}`);
    console.log(`SecretKey modified: ${!arrayEquals(originalSecretKey, keys.secretKey)}`);

    if (!arrayEquals(originalSecretKey, keys.secretKey)) {
      console.log(`\n!!! SECRET KEY WAS MODIFIED AFTER SECOND SIGN !!!`);
      findDifferences(originalSecretKey, keys.secretKey);
    }

    const sig3 = ml_dsa44.sign(msg, keys.secretKey);
    const isValid3 = ml_dsa44.verify(sig3, msg, keys.publicKey);
    console.log(`\n--- After Signature #3 ---`);
    console.log(`Signature #3 valid: ${isValid3}`);
    console.log(`SecretKey (first 64 bytes): ${toHex(keys.secretKey)}`);
    console.log(`SecretKey (bytes 2000-2064): ${toHex(keys.secretKey.subarray(2000, 2064))}`);
    console.log(`SecretKey modified: ${!arrayEquals(originalSecretKey, keys.secretKey)}`);

    if (!arrayEquals(originalSecretKey, keys.secretKey)) {
      console.log(`\n!!! SECRET KEY WAS MODIFIED AFTER THIRD SIGN !!!`);
      findDifferences(originalSecretKey, keys.secretKey);
    }
  });
});

function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function findDifferences(original: Uint8Array, modified: Uint8Array) {
  let firstDiff = -1;
  let lastDiff = -1;
  let diffCount = 0;

  for (let i = 0; i < original.length; i++) {
    if (original[i] !== modified[i]) {
      if (firstDiff === -1) firstDiff = i;
      lastDiff = i;
      diffCount++;
    }
  }

  console.log(`\nDifferences found:`);
  console.log(`  Total bytes modified: ${diffCount} / ${original.length}`);
  console.log(`  First difference at byte: ${firstDiff}`);
  console.log(`  Last difference at byte: ${lastDiff}`);
  console.log(`  Range: ${firstDiff} to ${lastDiff} (${lastDiff - firstDiff + 1} bytes)`);

  if (firstDiff !== -1) {
    const start = Math.max(0, firstDiff - 10);
    const end = Math.min(original.length, lastDiff + 10);
    console.log(`\n  Original [${start}:${end}]: ${toHex(original.subarray(start, end), end - start)}`);
    console.log(`  Modified [${start}:${end}]: ${toHex(modified.subarray(start, end), end - start)}`);
  }
}

should.runWhen(import.meta.url);

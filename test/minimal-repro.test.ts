import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

function toHex(arr: Uint8Array, len = 16): string {
  return Array.from(arr.slice(0, len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Minimal Repro', () => {
  should('find the exact iteration where it fails', () => {
    console.log('\n=== Starting test with fresh keypair ===');

    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    console.log(`PublicKey: ${toHex(keys.publicKey, 32)}`);
    console.log(`SecretKey: ${toHex(keys.secretKey, 32)}`);
    console.log(`Message: ${toHex(msg, msg.length)}`);

    const signatures = [];

    for (let i = 0; i < 100; i++) {
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);

      signatures.push({ sig, isValid, iteration: i + 1 });

      console.log(`\n#${i + 1}: ${isValid ? 'VALID' : 'INVALID'} - sig: ${toHex(sig, 32)}`);

      if (!isValid) {
        console.log(`\n!!! FIRST FAILURE AT ITERATION #${i + 1} !!!`);
        console.log(`\nComparing with last valid signature (#${i}):`);

        if (i > 0) {
          const lastValid = signatures[i - 1];
          console.log(`  Last valid sig: ${toHex(lastValid.sig, 32)}`);
          console.log(`  Failed sig:     ${toHex(sig, 32)}`);
          console.log(`  Signatures same: ${toHex(lastValid.sig, 32) === toHex(sig, 32)}`);
        }

        // Try signing again to see if it's consistent
        console.log(`\nTrying to sign again with same key:`);
        const sig2 = ml_dsa44.sign(msg, keys.secretKey);
        const isValid2 = ml_dsa44.verify(sig2, msg, keys.publicKey);
        console.log(`  Second attempt: ${isValid2 ? 'VALID' : 'INVALID'}`);

        // Check if secretKey is still intact by generating publicKey
        const regenPubKey = ml_dsa44.getPublicKey(keys.secretKey);
        const pubKeyMatch = toHex(regenPubKey, 64) === toHex(keys.publicKey, 64);
        console.log(`  PublicKey regeneration matches: ${pubKeyMatch}`);
        if (!pubKeyMatch) {
          console.log(`    Original: ${toHex(keys.publicKey, 64)}`);
          console.log(`    Regenerated: ${toHex(regenPubKey, 64)}`);
        }

        throw new Error(`Failed at iteration #${i + 1}`);
      }
    }

    console.log(`\n=== All 100 signatures valid ===`);
  });
});

should.runWhen(import.meta.url);

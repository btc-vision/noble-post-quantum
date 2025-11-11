import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

describe('Test Verify', () => {
  should('verify the same signature multiple times', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    // Create one signature
    const sig = ml_dsa44.sign(msg, keys.secretKey);

    console.log('\nVerifying the SAME signature 50 times:');
    for (let i = 0; i < 50; i++) {
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);
      if (i % 10 === 0 || !isValid) {
        console.log(`  Verification #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
      }
      if (!isValid) {
        throw new Error(`Verification #${i + 1} failed for the same signature!`);
      }
    }

    console.log('\nAll 50 verifications passed!');
  });

  should('verify different signatures', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    console.log('\nCreating and verifying 50 different signatures:');
    const signatures = [];

    for (let i = 0; i < 50; i++) {
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      signatures.push(sig);

      if (i % 10 === 0) {
        console.log(`  Created signature #${i + 1}`);
      }
    }

    console.log('\nNow verifying all 50 signatures:');
    for (let i = 0; i < signatures.length; i++) {
      const isValid = ml_dsa44.verify(signatures[i], msg, keys.publicKey);

      if (i % 10 === 0 || !isValid) {
        console.log(`  Verification of sig #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
      }

      if (!isValid) {
        throw new Error(`Verification of signature #${i + 1} failed!`);
      }
    }

    console.log('\nAll 50 signatures verified successfully!');
  });
});

should.runWhen(import.meta.url);

import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

describe('Simple Repeat Test', () => {
  should('sign 10 times in a row', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    for (let i = 0; i < 10; i++) {
      console.log(`\nSignature #${i + 1}`);
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);
      console.log(`  Valid: ${isValid}`);

      if (!isValid) {
        throw new Error(`Signature #${i + 1} is invalid!`);
      }
    }

    console.log(`\nAll 10 signatures valid!`);
  });
});

should.runWhen(import.meta.url);

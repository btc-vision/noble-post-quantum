import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

describe('Fifty Repeat Test', () => {
  should('sign 50 times in a row', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    for (let i = 0; i < 50; i++) {
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);

      if (i % 10 === 0 || !isValid) {
        console.log(`Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
      }

      if (!isValid) {
        throw new Error(`Signature #${i + 1} is invalid!`);
      }
    }

    console.log(`\nAll 50 signatures valid!`);
  });
});

should.runWhen(import.meta.url);

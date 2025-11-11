import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

describe('Just Five', () => {
  should('sign just 5 times', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    for (let i = 0; i < 5; i++) {
      console.log(`\n\n#################### SIGNATURE #${i + 1} ####################`);
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);
      console.log(`\n>>> RESULT: ${isValid ? 'VALID' : 'INVALID'} <<<\n`);

      if (!isValid) {
        throw new Error(`Signature #${i + 1} is invalid!`);
      }
    }

    console.log('\nAll 5 signatures valid!');
  });
});

should.runWhen(import.meta.url);

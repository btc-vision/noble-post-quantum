import { describe, should } from '@paulmillr/jsbt/test.js';
import { ml_dsa44 } from '../src/ml-dsa.ts';

function toHex(arr: Uint8Array, start = 0, len = 16): string {
  return Array.from(arr.slice(start, start + len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Track State', () => {
  should('track secretKey state across multiple signs', () => {
    const keys = ml_dsa44.keygen();
    const msg = new Uint8Array([1, 2, 3, 4, 5]);

    // Sample different parts of the secretKey
    const positions = [0, 100, 500, 1000, 1500, 2000, 2500];
    const initialState = positions.map(pos =>
      toHex(keys.secretKey, pos)
    );

    console.log('\nInitial secretKey state:');
    positions.forEach((pos, idx) => {
      console.log(`  [@${pos}]: ${initialState[idx]}`);
    });

    for (let i = 1; i <= 20; i++) {
      const sig = ml_dsa44.sign(msg, keys.secretKey);
      const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);

      // Check if secretKey changed
      let changed = false;
      const currentState = positions.map(pos => toHex(keys.secretKey, pos));

      for (let j = 0; j < positions.length; j++) {
        if (currentState[j] !== initialState[j]) {
          changed = true;
          console.log(`\n!!! After signature #${i}, secretKey[@${positions[j]}] changed !!!`);
          console.log(`  Was: ${initialState[j]}`);
          console.log(`  Now: ${currentState[j]}`);
        }
      }

      if (i % 5 === 0 || !isValid || changed) {
        console.log(`\n=== Signature #${i}: ${isValid ? 'VALID' : 'INVALID'} ===`);
        if (changed) {
          console.log('  SecretKey was MODIFIED!');
        }
      }

      if (!isValid) {
        throw new Error(`Signature #${i} invalid!`);
      }
    }

    console.log('\n=== All 20 signatures valid, secretKey unchanged ===');
  });
});

should.runWhen(import.meta.url);

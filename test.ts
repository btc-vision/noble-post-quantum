import { ml_dsa44 } from './src/ml-dsa.ts';
import { randomBytes } from './utils.js';

const msg = new Uint8Array([1, 2, 3, 4, 5]);

console.log('Generating keypair...');

const keys = ml_dsa44.keygen();
console.log(`Public Key -> ${Buffer.from(keys.publicKey).toString('base64')}`);

for (let i = 0; i < 100; i++) {

  console.log(`\n========== ITERATION ${i + 1} ==========`);

  const sig = ml_dsa44.sign(msg, keys.secretKey, {
    extraEntropy: randomBytes(32)
  });

  console.log(`Signature generated -> ${Buffer.from(sig).toString('base64')}`);

  //setTimeout(() => {

  const valid = ml_dsa44.verify(sig, msg, keys.publicKey);

  console.log(`RESULT: ${valid ? 'VALID ✓' : 'INVALID ✗'}`);

  if (!valid) {
    console.log('\n!!! FIRST FAILURE !!!\n');
    process.exit(0); // Exit successfully to show the failure case
  }
  //}, 100); // Yield to event loop

}

console.log('\nAll 100 passed!');

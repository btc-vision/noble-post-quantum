import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_shake_128f } from '../src/slh-dsa.ts';
import { randomBytes } from '../src/utils.ts';

// Helper to log hex of arrays for debugging
function toHex(arr: Uint8Array, len = 32): string {
  return Array.from(arr.slice(0, len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Repeated Signing Bug Tests', () => {
  describe('ML-DSA Repeated Signing', () => {
    for (const [name, algo] of Object.entries({
      'ml-dsa-44': ml_dsa44,
      'ml-dsa-65': ml_dsa65,
      'ml-dsa-87': ml_dsa87,
    })) {
      should(`${name}: sign 100 times with same keypair`, () => {
        console.log(`\n===== Testing ${name} with 100 signatures =====`);
        const keys = algo.keygen();
        console.log(`Generated keypair`);
        console.log(`  PublicKey (first 32 bytes): ${toHex(keys.publicKey)}`);
        console.log(`  SecretKey (first 32 bytes): ${toHex(keys.secretKey)}`);

        const msg = new Uint8Array([1, 2, 3, 4, 5]);
        const results = [];

        for (let i = 0; i < 100; i++) {
          console.log(`\n--- Signature #${i + 1} ---`);

          // Sign with random entropy (default behavior)
          const sig = algo.sign(msg, keys.secretKey);
          console.log(`  Signature generated (first 32 bytes): ${toHex(sig)}`);
          console.log(`  Signature length: ${sig.length}`);

          // Verify immediately
          const isValid = algo.verify(sig, msg, keys.publicKey);
          console.log(`  Immediate verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! FAILED AT SIGNATURE #${i + 1} !!!`);
            console.error(`  Message: ${toHex(msg, msg.length)}`);
            console.error(`  PublicKey: ${toHex(keys.publicKey)}`);
            console.error(`  SecretKey: ${toHex(keys.secretKey)}`);
            console.error(`  Signature: ${toHex(sig)}`);
            throw new Error(`Signature #${i + 1} is invalid immediately after signing!`);
          }

          results.push({ sig, isValid });
        }

        console.log(`\n===== Re-verifying all ${results.length} signatures =====`);
        for (let i = 0; i < results.length; i++) {
          const isValid = algo.verify(results[i].sig, msg, keys.publicKey);
          console.log(`  Signature #${i + 1} re-verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! RE-VERIFICATION FAILED FOR SIGNATURE #${i + 1} !!!`);
            throw new Error(`Signature #${i + 1} failed re-verification!`);
          }
        }

        console.log(`\n===== All ${results.length} signatures remain valid =====`);
      });

      should(`${name}: sign 1000 times with same keypair`, () => {
        console.log(`\n===== Testing ${name} with 1000 signatures =====`);
        const keys = algo.keygen();
        console.log(`Generated keypair`);

        const msg = new Uint8Array([1, 2, 3, 4, 5]);
        let failedAt = -1;

        for (let i = 0; i < 1000; i++) {
          const sig = algo.sign(msg, keys.secretKey);
          const isValid = algo.verify(sig, msg, keys.publicKey);

          if (i % 100 === 0) {
            console.log(`  Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
          }

          if (!isValid) {
            failedAt = i + 1;
            console.error(`\n!!! FAILED AT SIGNATURE #${failedAt} !!!`);
            console.error(`  Message: ${toHex(msg, msg.length)}`);
            console.error(`  Signature: ${toHex(sig)}`);
            throw new Error(`Signature #${failedAt} is invalid!`);
          }
        }

        console.log(`\n===== All 1000 signatures valid =====`);
      });

      should(`${name}: sign with deterministic entropy`, () => {
        console.log(`\n===== Testing ${name} with deterministic entropy =====`);
        const keys = algo.keygen();
        const msg = new Uint8Array([1, 2, 3, 4, 5]);
        const entropy = new Uint8Array(32).fill(42);

        console.log(`Generated keypair`);
        console.log(`Using fixed entropy: ${toHex(entropy)}`);

        for (let i = 0; i < 100; i++) {
          console.log(`\n--- Signature #${i + 1} (deterministic) ---`);
          const sig = algo.sign(msg, keys.secretKey, { extraEntropy: entropy });
          console.log(`  Signature (first 32 bytes): ${toHex(sig)}`);

          const isValid = algo.verify(sig, msg, keys.publicKey);
          console.log(`  Verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! FAILED AT SIGNATURE #${i + 1} (deterministic) !!!`);
            throw new Error(`Deterministic signature #${i + 1} is invalid!`);
          }
        }

        console.log(`\n===== All 100 deterministic signatures valid =====`);
      });

      should(`${name}: sign different messages`, () => {
        console.log(`\n===== Testing ${name} with different messages =====`);
        const keys = algo.keygen();

        for (let i = 0; i < 100; i++) {
          const msg = randomBytes(32);
          console.log(`\n--- Signature #${i + 1} ---`);
          console.log(`  Message: ${toHex(msg)}`);

          const sig = algo.sign(msg, keys.secretKey);
          const isValid = algo.verify(sig, msg, keys.publicKey);
          console.log(`  Verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! FAILED AT SIGNATURE #${i + 1} (different messages) !!!`);
            console.error(`  Message: ${toHex(msg)}`);
            throw new Error(`Signature #${i + 1} with different message is invalid!`);
          }
        }

        console.log(`\n===== All 100 signatures with different messages valid =====`);
      });
    }
  });

  describe('SLH-DSA Repeated Signing', () => {
    for (const [name, algo] of Object.entries({
      'slh-dsa-sha2-128f': slh_dsa_sha2_128f,
      'slh-dsa-sha2-128s': slh_dsa_sha2_128s,
      'slh-dsa-shake-128f': slh_dsa_shake_128f,
    })) {
      should(`${name}: sign 100 times with same keypair`, () => {
        console.log(`\n===== Testing ${name} with 100 signatures =====`);
        const keys = algo.keygen();
        console.log(`Generated keypair`);
        console.log(`  PublicKey (first 32 bytes): ${toHex(keys.publicKey)}`);
        console.log(`  SecretKey (first 32 bytes): ${toHex(keys.secretKey)}`);

        const msg = new Uint8Array([1, 2, 3, 4, 5]);
        const results = [];

        for (let i = 0; i < 100; i++) {
          console.log(`\n--- Signature #${i + 1} ---`);

          const sig = algo.sign(msg, keys.secretKey);
          console.log(`  Signature generated (first 32 bytes): ${toHex(sig)}`);
          console.log(`  Signature length: ${sig.length}`);

          const isValid = algo.verify(sig, msg, keys.publicKey);
          console.log(`  Immediate verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! FAILED AT SIGNATURE #${i + 1} !!!`);
            console.error(`  Message: ${toHex(msg, msg.length)}`);
            console.error(`  PublicKey: ${toHex(keys.publicKey)}`);
            console.error(`  SecretKey: ${toHex(keys.secretKey)}`);
            console.error(`  Signature: ${toHex(sig)}`);
            throw new Error(`Signature #${i + 1} is invalid immediately after signing!`);
          }

          results.push({ sig, isValid });
        }

        console.log(`\n===== Re-verifying all ${results.length} signatures =====`);
        for (let i = 0; i < results.length; i++) {
          const isValid = algo.verify(results[i].sig, msg, keys.publicKey);
          console.log(`  Signature #${i + 1} re-verification: ${isValid ? 'VALID' : 'INVALID'}`);

          if (!isValid) {
            console.error(`\n!!! RE-VERIFICATION FAILED FOR SIGNATURE #${i + 1} !!!`);
            throw new Error(`Signature #${i + 1} failed re-verification!`);
          }
        }

        console.log(`\n===== All ${results.length} signatures remain valid =====`);
      });

      should(`${name}: sign 500 times with same keypair`, () => {
        console.log(`\n===== Testing ${name} with 500 signatures =====`);
        const keys = algo.keygen();
        console.log(`Generated keypair`);

        const msg = new Uint8Array([1, 2, 3, 4, 5]);

        for (let i = 0; i < 500; i++) {
          const sig = algo.sign(msg, keys.secretKey);
          const isValid = algo.verify(sig, msg, keys.publicKey);

          if (i % 50 === 0) {
            console.log(`  Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
          }

          if (!isValid) {
            console.error(`\n!!! FAILED AT SIGNATURE #${i + 1} !!!`);
            console.error(`  Message: ${toHex(msg, msg.length)}`);
            console.error(`  Signature: ${toHex(sig)}`);
            throw new Error(`Signature #${i + 1} is invalid!`);
          }
        }

        console.log(`\n===== All 500 signatures valid =====`);
      });
    }
  });

  describe('Edge Cases', () => {
    should('ML-DSA-44: concurrent signing with same key', () => {
      console.log(`\n===== Testing concurrent signing =====`);
      const keys = ml_dsa44.keygen();
      const msg = new Uint8Array([1, 2, 3, 4, 5]);

      const signatures = [];
      for (let i = 0; i < 50; i++) {
        signatures.push(ml_dsa44.sign(msg, keys.secretKey));
      }

      console.log(`Generated ${signatures.length} signatures`);

      for (let i = 0; i < signatures.length; i++) {
        const isValid = ml_dsa44.verify(signatures[i], msg, keys.publicKey);
        console.log(`  Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);

        if (!isValid) {
          console.error(`\n!!! Concurrent signature #${i + 1} INVALID !!!`);
          throw new Error(`Concurrent signature #${i + 1} is invalid!`);
        }
      }

      console.log(`\n===== All concurrent signatures valid =====`);
    });

    should('ML-DSA-44: empty message repeated signing', () => {
      console.log(`\n===== Testing empty message signing =====`);
      const keys = ml_dsa44.keygen();
      const msg = new Uint8Array(0);

      for (let i = 0; i < 100; i++) {
        const sig = ml_dsa44.sign(msg, keys.secretKey);
        const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);

        if (i % 20 === 0) {
          console.log(`  Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
        }

        if (!isValid) {
          console.error(`\n!!! Empty message signature #${i + 1} INVALID !!!`);
          throw new Error(`Empty message signature #${i + 1} is invalid!`);
        }
      }

      console.log(`\n===== All empty message signatures valid =====`);
    });

    should('ML-DSA-44: large message repeated signing', () => {
      console.log(`\n===== Testing large message signing =====`);
      const keys = ml_dsa44.keygen();
      const msg = randomBytes(10000); // 10KB message

      console.log(`Message size: ${msg.length} bytes`);

      for (let i = 0; i < 50; i++) {
        const sig = ml_dsa44.sign(msg, keys.secretKey);
        const isValid = ml_dsa44.verify(sig, msg, keys.publicKey);

        if (i % 10 === 0) {
          console.log(`  Signature #${i + 1}: ${isValid ? 'VALID' : 'INVALID'}`);
        }

        if (!isValid) {
          console.error(`\n!!! Large message signature #${i + 1} INVALID !!!`);
          throw new Error(`Large message signature #${i + 1} is invalid!`);
        }
      }

      console.log(`\n===== All large message signatures valid =====`);
    });
  });
});

should.runWhen(import.meta.url);

/**
 * Example: All Security Levels and Parameter Combinations
 *
 * Demonstrates threshold signing across all three ML-DSA security levels
 * and various (T, N) configurations.
 *
 * Security levels:
 *   ML-DSA-44  — NIST Level 2 (128-bit classical)
 *   ML-DSA-65  — NIST Level 3 (192-bit classical)
 *   ML-DSA-87  — NIST Level 5 (256-bit classical)
 *
 * Run with: node --experimental-strip-types --no-warnings examples/threshold-all-security-levels.ts
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ThresholdMLDSA } from '../src/threshold-ml-dsa.ts';

const verifiers: Record<number, typeof ml_dsa44> = {
  44: ml_dsa44,
  65: ml_dsa65,
  87: ml_dsa87,
};

const configs = [
  // [securityLevel, T, N]
  [44, 2, 2],
  [44, 2, 3],
  [44, 3, 4],
  [44, 2, 4],
  [44, 3, 5],
  [44, 4, 6],
  [65, 2, 3],
  [65, 3, 5],
  [87, 2, 3],
  [87, 2, 4],
];

const message = new TextEncoder().encode('Testing all parameter combinations');

for (const [level, T, N] of configs) {
  const th = ThresholdMLDSA.create(level, T, N);
  const { publicKey, shares } = th.keygen();

  // Sign with exactly T shares
  const activeShares = shares.slice(0, T);
  const sig = th.sign(message, publicKey, activeShares);

  const valid = verifiers[level].verify(sig, message, publicKey);
  const params = th.params;
  console.log(
    `ML-DSA-${level} (${T},${N}) K_iter=${params.K_iter}: ` +
      `pk=${publicKey.length}B sig=${sig.length}B valid=${valid}`
  );
}

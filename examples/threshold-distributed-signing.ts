/**
 * Example: Distributed Threshold Signing Protocol (3 rounds)
 *
 * Demonstrates the full network-distributed signing protocol where
 * each party runs independently. This is the protocol you'd use
 * when parties are on different machines communicating over a network.
 *
 * The protocol has 3 rounds:
 *   Round 1: Each party generates a commitment hash (broadcast)
 *   Round 2: After receiving all hashes, each party reveals their commitment (broadcast)
 *   Round 3: After receiving all commitments, each party computes a partial response (broadcast)
 *   Combine: Anyone aggregates commitments + responses into a FIPS 204 signature
 *
 * Combine may return null due to norm check rejection (probabilistic).
 * In production, wrap rounds 1-3 + combine in a retry loop.
 *
 * Run with: node --experimental-strip-types --no-warnings examples/threshold-distributed-signing.ts
 */
import { ml_dsa65 } from '../src/ml-dsa.ts';
import { ThresholdMLDSA } from '../src/threshold-ml-dsa.ts';

// 2-of-3 threshold with ML-DSA-65
const th = ThresholdMLDSA.create(65, 2, 3);
const { publicKey, shares } = th.keygen();

const message = new TextEncoder().encode('Distributed signing example');

// Active signers: parties 0 and 1
const activeShares = [shares[0], shares[1]];
const activePartyIds = activeShares.map((s) => s.id);

// The distributed protocol is probabilistic — combine() may return null
// if this attempt's random commitments don't pass norm checks.
// In production, retry from Round 1 with fresh randomness.
let signature: Uint8Array | null = null;

for (let attempt = 0; attempt < 100 && !signature; attempt++) {
  // ============================================================
  // Round 1: Each party generates a commitment
  // ============================================================
  // In a real deployment, each party runs this independently.
  const round1Results = activeShares.map((share) => th.round1(share, { nonce: attempt }));

  // Each party broadcasts ONLY the commitmentHash (32 bytes).
  const round1Hashes = round1Results.map((r) => r.commitmentHash);

  if (attempt === 0) {
    console.log('--- Round 1: Commit ---');
    console.log(`Party 0 commitment hash: ${round1Hashes[0].length} bytes`);
    console.log(`Party 1 commitment hash: ${round1Hashes[1].length} bytes`);
  }

  // ============================================================
  // Round 2: After receiving all hashes, reveal commitments
  // ============================================================
  const round2Results = activeShares.map((share, i) =>
    th.round2(share, activePartyIds, message, round1Hashes, round1Results[i].state)
  );
  const commitments = round2Results.map((r) => r.commitment);

  if (attempt === 0) {
    console.log('\n--- Round 2: Reveal ---');
    console.log(`Party 0 commitment: ${commitments[0].length} bytes`);
    console.log(`Party 1 commitment: ${commitments[1].length} bytes`);
  }

  // ============================================================
  // Round 3: After receiving all commitments, compute responses
  // ============================================================
  const responses = activeShares.map((share, i) =>
    th.round3(share, commitments, round1Results[i].state, round2Results[i].state)
  );

  if (attempt === 0) {
    console.log('\n--- Round 3: Respond ---');
    console.log(`Party 0 response: ${responses[0].length} bytes`);
    console.log(`Party 1 response: ${responses[1].length} bytes`);
  }

  // ============================================================
  // Combine: Aggregate into a standard FIPS 204 signature
  // ============================================================
  signature = th.combine(publicKey, message, commitments, responses);

  // Clean up sensitive state
  for (const r of round1Results) r.state.destroy();
  for (const r of round2Results) r.state.destroy();

  if (!signature && attempt === 0) {
    console.log('\n--- Combine ---');
    console.log('Attempt 1 rejected (norm check) — retrying...');
  }
  if (signature) {
    console.log(`\n--- Combine (attempt ${attempt + 1}) ---`);
  }
}

if (signature) {
  console.log(`Signature: ${signature.length} bytes`);
  const valid = ml_dsa65.verify(signature, message, publicKey);
  console.log(`Verified with ml_dsa65.verify(): ${valid}`);
} else {
  console.log('Failed after 100 attempts');
}

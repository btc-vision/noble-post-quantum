/**
 * Example: Distributed Key Generation (DKG) — No Trusted Dealer
 *
 * Demonstrates the full 4-phase DKG protocol where NO single party
 * ever holds the complete secret key, even temporarily.
 *
 * Phase 1: Each party commits to their entropy (broadcast)
 * Phase 2: Each party reveals entropy, fellow holders verify and derive seeds
 * Phase 3: Generators distribute masked public key pieces (private)
 * Phase 4: Each party aggregates masks and broadcasts their aggregate
 * Finalize: All parties compute the public key and build their key shares
 *
 * The resulting public key and signatures are standard FIPS 204 ML-DSA —
 * indistinguishable from non-threshold or trusted-dealer usage.
 *
 * IMPORTANT: This protocol REQUIRES authenticated confidential channels
 * between all parties for Phase 2 (seed reveals) and Phase 3 (mask pieces).
 *
 * Run with: node --experimental-strip-types --no-warnings examples/threshold-dkg.ts
 */
import { ml_dsa44 } from '../src/ml-dsa.ts';
import {
  ThresholdMLDSA,
  type DKGPhase1Broadcast,
  type DKGPhase1State,
  type DKGPhase2Broadcast,
  type DKGPhase2Private,
  type DKGPhase3Private,
  type DKGPhase2FinalizeResult,
} from '../src/threshold-ml-dsa.ts';

// 2-of-3 threshold with ML-DSA-44
const T = 2;
const N = 3;
const th = ThresholdMLDSA.create(44, T, N);

// Session ID: unique 32-byte identifier for this DKG instance.
// All parties must agree on this before starting.
const sessionId = crypto.getRandomValues(new Uint8Array(32));

// ============================================================
// Phase 0: Setup (deterministic, all parties compute locally)
// ============================================================
const { bitmasks, holdersOf } = th.dkgSetup(sessionId);
console.log(`Bitmasks: ${bitmasks.length} (C(${N}, ${N - T + 1}) subsets)`);
for (const [b, holders] of holdersOf) {
  console.log(`  Bitmask 0b${b.toString(2).padStart(N, '0')}: holders [${holders.join(', ')}]`);
}

// ============================================================
// Phase 1: Commit (each party independently)
// ============================================================
console.log('\n--- Phase 1: Commit ---');
const phase1: { broadcast: DKGPhase1Broadcast; state: DKGPhase1State }[] = [];
for (let i = 0; i < N; i++) {
  phase1.push(th.dkgPhase1(i, sessionId));
  console.log(`Party ${i}: committed rho + ${phase1[i].broadcast.bitmaskCommitments.size} bitmask seeds`);
}
// All parties exchange Phase 1 broadcasts (public channel).
const allPhase1 = phase1.map((r) => r.broadcast);

// ============================================================
// Phase 2: Reveal (broadcast rho, private seed reveals)
// ============================================================
console.log('\n--- Phase 2: Reveal ---');
const phase2: {
  broadcast: DKGPhase2Broadcast;
  privateToHolders: Map<number, DKGPhase2Private>;
}[] = [];
for (let i = 0; i < N; i++) {
  phase2.push(th.dkgPhase2(i, sessionId, phase1[i].state, allPhase1));
  console.log(`Party ${i}: revealed rho, sending private reveals to ${phase2[i].privateToHolders.size} fellow holders`);
}
// All parties exchange Phase 2 broadcasts (public channel).
const allPhase2 = phase2.map((r) => r.broadcast);

// Simulate private channel delivery: route each party's reveals to recipients.
const receivedReveals: DKGPhase2Private[][] = Array.from({ length: N }, () => []);
for (let i = 0; i < N; i++) {
  for (const [targetId, msg] of phase2[i].privateToHolders) {
    receivedReveals[targetId].push(msg);
  }
}

// ============================================================
// Phase 2 Finalize + Phase 3: Verify, derive, and distribute masks
// ============================================================
console.log('\n--- Phase 2 Finalize + Phase 3: Derive & Mask ---');
const finalize: DKGPhase2FinalizeResult[] = [];
for (let i = 0; i < N; i++) {
  finalize.push(
    th.dkgPhase2Finalize(i, sessionId, phase1[i].state, allPhase1, allPhase2, receivedReveals[i])
  );
  const genCount = [...finalize[i].generatorAssignment.values()].filter((g) => g === i).length;
  console.log(`Party ${i}: derived ${finalize[i].shares.size} shares, generator for ${genCount} bitmasks`);
}

// Simulate private channel delivery: route mask pieces to recipients.
const receivedMasks: DKGPhase3Private[][] = Array.from({ length: N }, () => []);
for (let i = 0; i < N; i++) {
  for (const [targetId, msg] of finalize[i].privateToAll) {
    receivedMasks[targetId].push(msg);
  }
}

// ============================================================
// Phase 4: Aggregate masks and broadcast R_j
// ============================================================
console.log('\n--- Phase 4: Aggregate ---');
const phase4 = [];
for (let i = 0; i < N; i++) {
  phase4.push(
    th.dkgPhase4(
      i,
      bitmasks,
      finalize[i].generatorAssignment,
      receivedMasks[i],
      finalize[i].ownMaskPieces
    )
  );
  console.log(`Party ${i}: computed R_${i} aggregate`);
}

// ============================================================
// Finalize: Compute public key and build key shares
// ============================================================
console.log('\n--- Finalize ---');
const results = [];
for (let i = 0; i < N; i++) {
  results.push(th.dkgFinalize(i, finalize[i].rho, phase4, finalize[i].shares));
}

const publicKey = results[0].publicKey;
console.log(`Public key (${publicKey.length} bytes)`);

// Verify all parties agree on the same public key
const allAgree = results.every((r) => {
  if (r.publicKey.length !== publicKey.length) return false;
  for (let i = 0; i < publicKey.length; i++) {
    if (r.publicKey[i] !== publicKey[i]) return false;
  }
  return true;
});
console.log(`All parties agree on public key: ${allAgree}`);

// ============================================================
// Sign with DKG shares — standard threshold signing
// ============================================================
console.log('\n--- Threshold Signing with DKG Shares ---');
const message = new TextEncoder().encode('Signed without any trusted dealer!');

// Use any T shares to sign
const dkgShares = results.map((r) => r.share);
const signature = th.sign(message, publicKey, [dkgShares[0], dkgShares[1]]);
console.log(`Signature (${signature.length} bytes)`);

// Verify with standard ML-DSA — no threshold knowledge needed
const valid = ml_dsa44.verify(signature, message, publicKey);
console.log(`Verified with ml_dsa44.verify(): ${valid}`);

// Different subset also works
const sig2 = th.sign(message, publicKey, [dkgShares[1], dkgShares[2]]);
console.log(`Different subset valid: ${ml_dsa44.verify(sig2, message, publicKey)}`);

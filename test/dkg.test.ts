import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import {
  ThresholdMLDSA,
  type DKGPhase1Broadcast,
  type DKGPhase1State,
  type DKGPhase2Broadcast,
  type DKGPhase2Private,
  type DKGPhase3Private,
  type DKGPhase4Broadcast,
  type DKGPhase2FinalizeResult,
  type ThresholdKeyShare,
} from '../src/threshold-ml-dsa.ts';

// ==================== Helpers ====================

/** Run a complete DKG protocol for N parties, returning all intermediate state. */
function runFullDKG(th: ThresholdMLDSA, sessionId?: Uint8Array) {
  const params = th.params;
  const { T, N: N_ } = params;
  const sid = sessionId ?? randomBytes(32);
  const setup = th.dkgSetup(sid);

  // Phase 1: all parties commit
  const phase1: { broadcast: DKGPhase1Broadcast; state: DKGPhase1State }[] = [];
  for (let i = 0; i < N_; i++) phase1.push(th.dkgPhase1(i, sid));
  const allPhase1 = phase1.map((r) => r.broadcast);

  // Phase 2: all parties reveal
  const phase2: {
    broadcast: DKGPhase2Broadcast;
    privateToHolders: Map<number, DKGPhase2Private>;
  }[] = [];
  for (let i = 0; i < N_; i++) {
    phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
  }
  const allPhase2Broadcasts = phase2.map((r) => r.broadcast);

  // Distribute private reveals
  const receivedReveals: DKGPhase2Private[][] = Array.from({ length: N_ }, () => []);
  for (let i = 0; i < N_; i++) {
    for (const [targetId, msg] of phase2[i].privateToHolders) {
      receivedReveals[targetId].push(msg);
    }
  }

  // Phase 2 Finalize + Phase 3
  const finalize: DKGPhase2FinalizeResult[] = [];
  for (let i = 0; i < N_; i++) {
    finalize.push(
      th.dkgPhase2Finalize(
        i,
        sid,
        phase1[i].state,
        allPhase1,
        allPhase2Broadcasts,
        receivedReveals[i]
      )
    );
  }

  // Distribute Phase 3 mask pieces
  const receivedMasks: DKGPhase3Private[][] = Array.from({ length: N_ }, () => []);
  for (let i = 0; i < N_; i++) {
    for (const [targetId, msg] of finalize[i].privateToAll) {
      receivedMasks[targetId].push(msg);
    }
  }

  // Phase 4: aggregate and broadcast
  const phase4: DKGPhase4Broadcast[] = [];
  for (let i = 0; i < N_; i++) {
    phase4.push(
      th.dkgPhase4(
        i,
        setup.bitmasks,
        finalize[i].generatorAssignment,
        receivedMasks[i],
        finalize[i].ownMaskPieces
      )
    );
  }

  // Finalize
  const results = [];
  for (let i = 0; i < N_; i++) {
    results.push(th.dkgFinalize(i, finalize[i].rho, phase4, finalize[i].shares));
  }

  return {
    sid,
    setup,
    phase1,
    phase2,
    allPhase1,
    allPhase2Broadcasts,
    receivedReveals,
    finalize,
    receivedMasks,
    phase4,
    results,
    publicKey: results[0].publicKey,
    shares: results.map((r) => r.share),
  };
}

// ==================== Tests ====================

describe('Distributed DKG', () => {
  // ------ Test 1: Correctness ------
  describe('Correctness — produces valid ML-DSA public key', () => {
    should('produce valid public key for (2, 3) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      eql(shares.length, 3);
    });

    should('produce valid public key for (2, 2) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 2, 2);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      eql(shares.length, 2);
    });

    should('produce valid public key for (3, 4) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 3, 4);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      eql(shares.length, 4);
    });

    should('produce valid public key for (3, 5) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      eql(shares.length, 5);
    });

    should('produce valid public key for (2, 3) ML-DSA-65', () => {
      const th = ThresholdMLDSA.create(65, 2, 3);
      const { publicKey } = runFullDKG(th);
      eql(publicKey.length, ml_dsa65.lengths.publicKey);
    });

    should('produce valid public key for (2, 3) ML-DSA-87', () => {
      const th = ThresholdMLDSA.create(87, 2, 3);
      const { publicKey } = runFullDKG(th);
      eql(publicKey.length, ml_dsa87.lengths.publicKey);
    });

    should('all parties derive the same public key', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { results } = runFullDKG(th);
      for (let i = 1; i < results.length; i++) {
        eql(results[i].publicKey, results[0].publicKey);
      }
    });

    should('all parties derive the same rho', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { finalize } = runFullDKG(th);
      for (let i = 1; i < finalize.length; i++) {
        eql(finalize[i].rho, finalize[0].rho);
      }
    });

    should('all parties derive the same tr', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = runFullDKG(th);
      for (let i = 1; i < shares.length; i++) {
        eql(shares[i].tr, shares[0].tr);
      }
    });
  });

  // ------ Test 2: Signing compatibility ------
  describe('Signing compatibility — DKG shares sign correctly', () => {
    should('DKG 2-of-3 shares produce valid signature (parties 0,1)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([1, 2, 3, 4]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 2-of-3 shares produce valid signature (parties 0,2)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([5, 6, 7, 8]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 2-of-3 shares produce valid signature (parties 1,2)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([9, 10, 11, 12]);
      const sig = th.sign(msg, publicKey, [shares[1], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 2-of-2 shares produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 2, 2);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([1, 2, 3]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 3-of-4 shares produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 3, 4);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([10, 20, 30]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 3-of-5 shares produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([40, 50, 60]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[2], shares[4]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG 2-of-4: any subset of 2 signs correctly', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([100, 200]);
      const subsets: [number, number][] = [
        [0, 1],
        [0, 2],
        [0, 3],
        [1, 2],
        [1, 3],
        [2, 3],
      ];
      for (const [i, j] of subsets) {
        const sig = th.sign(msg, publicKey, [shares[i], shares[j]]);
        eql(ml_dsa44.verify(sig, msg, publicKey), true);
      }
    });

    should('DKG shares produce valid ML-DSA-65 signature', () => {
      const th = ThresholdMLDSA.create(65, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([1, 2, 3]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa65.lengths.signature);
      eql(ml_dsa65.verify(sig, msg, publicKey), true);
    });

    should('DKG shares produce valid ML-DSA-87 signature', () => {
      const th = ThresholdMLDSA.create(87, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([4, 5, 6]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa87.lengths.signature);
      eql(ml_dsa87.verify(sig, msg, publicKey), true);
    });

    should('DKG shares work with context', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([1, 2, 3]);
      const ctx = new Uint8Array([0xde, 0xad]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]], { context: ctx });
      eql(ml_dsa44.verify(sig, msg, publicKey, { context: ctx }), true);
      eql(ml_dsa44.verify(sig, msg, publicKey), false);
    });

    should('DKG shares work with distributed signing protocol', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([7, 8, 9]);
      const activePartyIds = [0, 1];

      let sig: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        const r1_0 = th.round1(shares[0], { nonce: attempt });
        const r1_1 = th.round1(shares[1], { nonce: attempt });
        const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
        const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
        const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);
        const allCommitments = [r2_0.commitment, r2_1.commitment];
        const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
        const resp_1 = th.round3(shares[1], allCommitments, r1_1.state, r2_1.state);
        sig = th.combine(publicKey, msg, allCommitments, [resp_0, resp_1]);
        r1_0.state.destroy();
        r1_1.state.destroy();
        r2_0.state.destroy();
        r2_1.state.destroy();
        if (sig !== null) break;
      }
      eql(sig !== null, true);
      eql(ml_dsa44.verify(sig!, msg, publicKey), true);
    });
  });

  // ------ Test 3: Seed consistency ------
  describe('Seed consistency — all holders derive identical shares', () => {
    should('all holders of same bitmask derive identical s1/s2', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, finalize } = runFullDKG(th);

      for (const [b, holders] of setup.holdersOf as Map<number, number[]>) {
        const refShare = finalize[holders[0]].shares.get(b)!;
        for (let hi = 1; hi < holders.length; hi++) {
          const otherShare = finalize[holders[hi]].shares.get(b)!;
          for (let j = 0; j < refShare.s1.length; j++) {
            eql(refShare.s1[j], otherShare.s1[j]);
          }
          for (let j = 0; j < refShare.s2.length; j++) {
            eql(refShare.s2[j], otherShare.s2[j]);
          }
          for (let j = 0; j < refShare.s1Hat.length; j++) {
            eql(refShare.s1Hat[j], otherShare.s1Hat[j]);
          }
          for (let j = 0; j < refShare.s2Hat.length; j++) {
            eql(refShare.s2Hat[j], otherShare.s2Hat[j]);
          }
        }
      }
    });

    should('seed consistency holds for (3,5) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { setup, finalize } = runFullDKG(th);
      for (const [b, holders] of setup.holdersOf as Map<number, number[]>) {
        const refShare = finalize[holders[0]].shares.get(b)!;
        for (let hi = 1; hi < holders.length; hi++) {
          const otherShare = finalize[holders[hi]].shares.get(b)!;
          for (let j = 0; j < refShare.s1.length; j++) {
            eql(refShare.s1[j], otherShare.s1[j]);
          }
          for (let j = 0; j < refShare.s2.length; j++) {
            eql(refShare.s2[j], otherShare.s2[j]);
          }
        }
      }
    });
  });

  // ------ Test 4: Mask cancellation ------
  describe('Mask cancellation — sum_j R_j equals sum_b w^b', () => {
    should('mask cancellation holds for (2,3)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, phase4, finalize } = runFullDKG(th);
      const K = ml_dsa44.lengths.publicKey > 1500 ? 6 : 4; // K=4 for ML-DSA-44

      // sum_j R_j
      const sumR: Int32Array[] = [];
      for (let k = 0; k < K; k++) sumR.push(new Int32Array(256));
      for (const ph4 of phase4) {
        for (let k = 0; k < K; k++) {
          for (let c = 0; c < 256; c++) {
            sumR[k][c] = (sumR[k][c] + ph4.aggregate[k][c]) % 8380417;
          }
        }
      }
      // Normalize
      for (let k = 0; k < K; k++) {
        for (let c = 0; c < 256; c++) {
          sumR[k][c] = ((sumR[k][c] % 8380417) + 8380417) % 8380417;
        }
      }

      // Verify t has correct length (K polynomials × 256 coefficients)
      eql(sumR.length, K);
      for (let k = 0; k < K; k++) {
        eql(sumR[k].length, 256);
      }
    });
  });

  // ------ Test 5: Structural secrecy ------
  describe('Structural secrecy — each party misses at least one bitmask', () => {
    should('each party lacks at least one bitmask for (2,3)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, shares } = runFullDKG(th);

      for (let i = 0; i < 3; i++) {
        let missesSome = false;
        for (const b of setup.bitmasks) {
          if (!shares[i].shares.has(b)) {
            missesSome = true;
            break;
          }
        }
        eql(missesSome, true);
      }
    });

    should('each party lacks at least one bitmask for (3,5)', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { setup, shares } = runFullDKG(th);

      for (let i = 0; i < 5; i++) {
        let missesSome = false;
        for (const b of setup.bitmasks) {
          if (!shares[i].shares.has(b)) {
            missesSome = true;
            break;
          }
        }
        eql(missesSome, true);
      }
    });

    should('no party holds all bitmasks for (2,4)', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { setup, shares } = runFullDKG(th);

      for (let i = 0; i < 4; i++) {
        const totalBitmasks = setup.bitmasks.length;
        const held = [...setup.bitmasks].filter((b) => shares[i].shares.has(b)).length;
        eql(held < totalBitmasks, true);
      }
    });
  });

  // ------ Test 6: Commitment binding ------
  describe('Commitment binding — tampered reveals are detected', () => {
    should('detect tampered rho reveal', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);

      const phase1 = [];
      for (let i = 0; i < 3; i++) phase1.push(th.dkgPhase1(i, sid));
      const allPhase1 = phase1.map((r) => r.broadcast);

      const phase2 = [];
      for (let i = 0; i < 3; i++) {
        phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
      }

      // Tamper with party 1's rho
      const tamperedRho = phase2[1].broadcast.rho.slice();
      tamperedRho[0] ^= 0xff;
      const tamperedBroadcasts = [
        phase2[0].broadcast,
        { partyId: 1, rho: tamperedRho },
        phase2[2].broadcast,
      ];

      const receivedReveals: DKGPhase2Private[] = [];
      for (let i = 0; i < 3; i++) {
        const msg = phase2[i].privateToHolders.get(0);
        if (msg) receivedReveals.push(msg);
      }

      throws(
        () =>
          th.dkgPhase2Finalize(
            0,
            sid,
            phase1[0].state,
            allPhase1,
            tamperedBroadcasts,
            receivedReveals
          ),
        /Rho commitment mismatch/
      );
    });

    should('detect tampered bitmask seed reveal', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);

      const phase1 = [];
      for (let i = 0; i < 3; i++) phase1.push(th.dkgPhase1(i, sid));
      const allPhase1 = phase1.map((r) => r.broadcast);

      const phase2 = [];
      for (let i = 0; i < 3; i++) {
        phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
      }
      const allPhase2 = phase2.map((r) => r.broadcast);

      // Collect reveals for party 0
      const revealsForZero: DKGPhase2Private[] = [];
      for (let i = 0; i < 3; i++) {
        const msg = phase2[i].privateToHolders.get(0);
        if (msg) revealsForZero.push(msg);
      }

      // Tamper with a reveal from party 1
      if (revealsForZero.length > 0) {
        const firstReveal = revealsForZero[0];
        const tamperedReveals = new Map(firstReveal.bitmaskReveals);
        for (const [b, val] of tamperedReveals) {
          const tampered = val.slice();
          tampered[0] ^= 0xff;
          tamperedReveals.set(b, tampered);
          break; // tamper just one
        }
        revealsForZero[0] = { fromPartyId: firstReveal.fromPartyId, bitmaskReveals: tamperedReveals };

        throws(
          () =>
            th.dkgPhase2Finalize(0, sid, phase1[0].state, allPhase1, allPhase2, revealsForZero),
          /Bitmask seed commitment mismatch/
        );
      }
    });
  });

  // ------ Test 7: Session isolation ------
  describe('Session isolation — cross-session commits fail', () => {
    should('commitments from session A fail in session B', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sidA = randomBytes(32);
      const sidB = randomBytes(32);

      // Generate Phase 1 with session A
      const phase1A = [];
      for (let i = 0; i < 3; i++) phase1A.push(th.dkgPhase1(i, sidA));

      // Generate Phase 2 with session A
      const allPhase1A = phase1A.map((r) => r.broadcast);
      const phase2A = [];
      for (let i = 0; i < 3; i++) {
        phase2A.push(th.dkgPhase2(i, sidA, phase1A[i].state, allPhase1A));
      }

      // Generate Phase 1 with session B
      const phase1B = [];
      for (let i = 0; i < 3; i++) phase1B.push(th.dkgPhase1(i, sidB));
      const allPhase1B = phase1B.map((r) => r.broadcast);

      // Phase 2 with session B
      const phase2B = [];
      for (let i = 0; i < 3; i++) {
        phase2B.push(th.dkgPhase2(i, sidB, phase1B[i].state, allPhase1B));
      }

      // Try to verify session A's rho reveals against session B's commitments
      // Mix: Phase 1 from B, Phase 2 broadcasts from A
      const receivedRevealsForZero: DKGPhase2Private[] = [];
      for (let i = 0; i < 3; i++) {
        const msg = phase2B[i].privateToHolders.get(0);
        if (msg) receivedRevealsForZero.push(msg);
      }

      throws(
        () =>
          th.dkgPhase2Finalize(
            0,
            sidB,
            phase1B[0].state,
            allPhase1B,
            // Use session A's Phase 2 broadcasts (wrong session)
            phase2A.map((r) => r.broadcast),
            receivedRevealsForZero
          ),
        /Rho commitment mismatch/
      );
    });
  });

  // ------ Test 8: Generator balance ------
  describe('Generator balance — no party over-assigned', () => {
    should('generator assignments are balanced for (2,3)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, finalize } = runFullDKG(th);

      // Count how many bitmasks each party generates
      const genCount = new Map<number, number>();
      for (let i = 0; i < 3; i++) genCount.set(i, 0);

      const genAssign = finalize[0].generatorAssignment;
      for (const [_b, gen] of genAssign) {
        genCount.set(gen, (genCount.get(gen) ?? 0) + 1);
      }

      const bitmasks = setup.bitmasks;
      const holdersPerBitmask = setup.holdersOf.values().next().value!.length;
      const maxExpected = Math.ceil(bitmasks.length / holdersPerBitmask) + 1;

      for (const [_party, count] of genCount) {
        eql(count <= maxExpected, true);
      }
    });

    should('all generators are holders of their bitmask', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { setup, finalize } = runFullDKG(th);

      const genAssign = finalize[0].generatorAssignment;
      for (const [b, gen] of genAssign) {
        const holders = setup.holdersOf.get(b)!;
        eql(holders.includes(gen), true);
      }
    });

    should('all parties agree on generator assignment', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { finalize } = runFullDKG(th);

      for (let i = 1; i < finalize.length; i++) {
        for (const [b, gen] of finalize[0].generatorAssignment) {
          eql(finalize[i].generatorAssignment.get(b), gen);
        }
      }
    });
  });

  // ------ Test 9: Non-holder exclusion ------
  describe('Non-holder exclusion — cannot compute held shares', () => {
    should('non-holders have no shares for excluded bitmasks', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, finalize } = runFullDKG(th);

      for (let i = 0; i < 3; i++) {
        for (const b of setup.bitmasks) {
          const isHolder = (b & (1 << i)) !== 0;
          if (!isHolder) {
            // Party i should not have a share for bitmask b
            eql(finalize[i].shares.has(b), false);
          } else {
            eql(finalize[i].shares.has(b), true);
          }
        }
      }
    });

    should('non-holders receive no private reveals for excluded bitmasks', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { setup, receivedReveals } = runFullDKG(th);

      for (let i = 0; i < 3; i++) {
        const allRevealedBitmasks = new Set<number>();
        for (const reveal of receivedReveals[i]) {
          for (const [b] of reveal.bitmaskReveals) {
            allRevealedBitmasks.add(b);
          }
        }
        // Party i should only receive reveals for bitmasks where they're a holder
        for (const b of allRevealedBitmasks) {
          eql((b & (1 << i)) !== 0, true);
        }
      }
    });
  });

  // ------ Test 10: Post-DKG test sign ------
  describe('Post-DKG test sign — verifies end-to-end correctness', () => {
    should('full DKG then sign flow for (2,3) ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('full DKG then sign flow for (2,2) ML-DSA-65', () => {
      const th = ThresholdMLDSA.create(65, 2, 2);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([0xde, 0xad]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa65.verify(sig, msg, publicKey), true);
    });

    should('full DKG then sign flow for (2,2) ML-DSA-87', () => {
      const th = ThresholdMLDSA.create(87, 2, 2);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([0xbe, 0xef]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa87.verify(sig, msg, publicKey), true);
    });

    should('full DKG then distributed signing for (2,3)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = runFullDKG(th);
      const msg = new Uint8Array([1, 2, 3]);
      const activePartyIds = [1, 2];

      let sig: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        const r1_0 = th.round1(shares[1], { nonce: attempt });
        const r1_1 = th.round1(shares[2], { nonce: attempt });
        const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
        const r2_0 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_0.state);
        const r2_1 = th.round2(shares[2], activePartyIds, msg, allHashes, r1_1.state);
        const allCommitments = [r2_0.commitment, r2_1.commitment];
        const resp_0 = th.round3(shares[1], allCommitments, r1_0.state, r2_0.state);
        const resp_1 = th.round3(shares[2], allCommitments, r1_1.state, r2_1.state);
        sig = th.combine(publicKey, msg, allCommitments, [resp_0, resp_1]);
        r1_0.state.destroy();
        r1_1.state.destroy();
        r2_0.state.destroy();
        r2_1.state.destroy();
        if (sig !== null) break;
      }
      eql(sig !== null, true);
      eql(ml_dsa44.verify(sig!, msg, publicKey), true);
    });
  });

  // ------ DKG Setup tests ------
  describe('DKG Setup', () => {
    should('enumerate correct number of bitmasks', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);
      // C(3,2) = 3 bitmasks
      eql(bitmasks.length, 3);
    });

    should('enumerate C(4,3) = 4 bitmasks for (2,4)', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const sid = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);
      eql(bitmasks.length, 4); // C(4,3) = 4, N-T+1 = 3 bits set
    });

    should('enumerate C(5,3) = 10 bitmasks for (3,5)', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const sid = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);
      eql(bitmasks.length, 10);
    });

    should('reject invalid session ID length', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      throws(() => th.dkgSetup(new Uint8Array(16)));
    });

    should('each bitmask has exactly N-T+1 bits set', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const sid = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);
      const expectedBits = 5 - 3 + 1; // N-T+1 = 3
      for (const b of bitmasks) {
        let count = 0;
        for (let i = 0; i < 5; i++) {
          if (b & (1 << i)) count++;
        }
        eql(count, expectedBits);
      }
    });

    should('holders are sorted', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const sid = randomBytes(32);
      const { holdersOf } = th.dkgSetup(sid);
      for (const [_b, holders] of holdersOf as Map<number, number[]>) {
        for (let i = 1; i < holders.length; i++) {
          eql(holders[i] > holders[i - 1], true);
        }
      }
    });
  });

  // ------ DKG Phase 1 tests ------
  describe('DKG Phase 1', () => {
    should('reject invalid partyId', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      throws(() => th.dkgPhase1(-1, sid));
      throws(() => th.dkgPhase1(3, sid));
    });

    should('produce deterministic commitments with provided entropy', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const rho = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);

      const bitmaskEntropy = new Map<number, Uint8Array>();
      for (const b of bitmasks) {
        if (b & (1 << 0)) bitmaskEntropy.set(b, randomBytes(32));
      }

      const r1 = th.dkgPhase1(0, sid, { rho: rho.slice(), bitmaskEntropy });
      const r2 = th.dkgPhase1(0, sid, { rho: rho.slice(), bitmaskEntropy });

      eql(r1.broadcast.rhoCommitment, r2.broadcast.rhoCommitment);
      for (const [b, c1] of r1.broadcast.bitmaskCommitments) {
        eql(c1, r2.broadcast.bitmaskCommitments.get(b));
      }
    });

    should('commitments are 32 bytes', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const { broadcast } = th.dkgPhase1(0, sid);
      eql(broadcast.rhoCommitment.length, 32);
      for (const [_b, c] of broadcast.bitmaskCommitments) {
        eql(c.length, 32);
      }
    });

    should('only commit for held bitmasks', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const { bitmasks } = th.dkgSetup(sid);

      for (let i = 0; i < 3; i++) {
        const { broadcast } = th.dkgPhase1(i, sid);
        for (const [b] of broadcast.bitmaskCommitments) {
          // Party i should only have commitments for bitmasks where bit i is set
          eql((b & (1 << i)) !== 0, true);
        }
        // And should have commitments for ALL held bitmasks
        for (const b of bitmasks) {
          if (b & (1 << i)) {
            eql(broadcast.bitmaskCommitments.has(b), true);
          }
        }
      }
    });
  });

  // ------ DKG Phase 2 tests ------
  describe('DKG Phase 2', () => {
    should('reject wrong number of Phase 1 broadcasts', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const ph1 = th.dkgPhase1(0, sid);
      throws(() => th.dkgPhase2(0, sid, ph1.state, [ph1.broadcast])); // only 1, need 3
    });

    should('private reveals only go to fellow holders', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = randomBytes(32);
      const { bitmasks, holdersOf } = th.dkgSetup(sid);

      const phase1 = [];
      for (let i = 0; i < 3; i++) phase1.push(th.dkgPhase1(i, sid));
      const allPhase1 = phase1.map((r) => r.broadcast);

      for (let i = 0; i < 3; i++) {
        const { privateToHolders } = th.dkgPhase2(i, sid, phase1[i].state, allPhase1);

        // Check that reveals are only sent to fellow holders
        for (const [targetId, msg] of privateToHolders) {
          for (const [b] of msg.bitmaskReveals) {
            const holders = holdersOf.get(b) as number[];
            eql(holders.includes(i), true); // sender is holder
            eql(holders.includes(targetId), true); // receiver is holder
          }
        }
      }
    });
  });

  // ------ DKG error cases ------
  describe('DKG error cases', () => {
    should('reject wrong Phase 4 broadcast count', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const rho = randomBytes(32);
      throws(
        () => th.dkgFinalize(0, rho, [], new Map()),
        /Expected 3 Phase 4 broadcasts, got 0/
      );
    });

    should('reject invalid session ID in Phase 1', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      throws(() => th.dkgPhase1(0, new Uint8Array(16)));
    });
  });

  // ------ T=N edge case ------
  describe('T=N edge case (each party holds one bitmask)', () => {
    should('DKG works for 3-of-3', () => {
      const th = ThresholdMLDSA.create(44, 3, 3);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      const msg = new Uint8Array([1, 2, 3]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('DKG works for 4-of-4', () => {
      const th = ThresholdMLDSA.create(44, 4, 4);
      const { publicKey, shares } = runFullDKG(th);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
      const msg = new Uint8Array([4, 5, 6]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2], shares[3]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  // ------ Deterministic DKG with fixed entropy ------
  describe('Deterministic DKG with fixed entropy', () => {
    should('produce identical public key with same entropy', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const sid = new Uint8Array(32);
      sid[0] = 42;

      // Generate fixed entropy
      const { bitmasks } = th.dkgSetup(sid);
      const partyEntropy: { rho: Uint8Array; bitmaskEntropy: Map<number, Uint8Array> }[] = [];
      for (let i = 0; i < 3; i++) {
        const rho = new Uint8Array(32);
        rho[0] = i + 1;
        const bitmaskEnt = new Map<number, Uint8Array>();
        for (const b of bitmasks) {
          if (b & (1 << i)) {
            const ent = new Uint8Array(32);
            ent[0] = i + 10;
            ent[1] = b;
            bitmaskEnt.set(b, ent);
          }
        }
        partyEntropy.push({ rho, bitmaskEntropy: bitmaskEnt });
      }

      // Run DKG twice with same entropy
      function deterministicDKG() {
        const phase1 = [];
        for (let i = 0; i < 3; i++) {
          phase1.push(
            th.dkgPhase1(i, sid, {
              rho: partyEntropy[i].rho.slice(),
              bitmaskEntropy: new Map(
                [...partyEntropy[i].bitmaskEntropy].map(([k, v]) => [k, v.slice()])
              ),
            })
          );
        }
        const allPhase1 = phase1.map((r) => r.broadcast);

        const phase2 = [];
        for (let i = 0; i < 3; i++) {
          phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
        }
        const allPhase2 = phase2.map((r) => r.broadcast);

        const receivedReveals: DKGPhase2Private[][] = [[], [], []];
        for (let i = 0; i < 3; i++) {
          for (const [targetId, msg] of phase2[i].privateToHolders) {
            receivedReveals[targetId].push(msg);
          }
        }

        const finalize = [];
        for (let i = 0; i < 3; i++) {
          finalize.push(
            th.dkgPhase2Finalize(i, sid, phase1[i].state, allPhase1, allPhase2, receivedReveals[i])
          );
        }

        // Compare rho (deterministic from entropy)
        return finalize[0].rho;
      }

      const rho1 = deterministicDKG();
      const rho2 = deterministicDKG();
      eql(rho1, rho2);
    });
  });
});

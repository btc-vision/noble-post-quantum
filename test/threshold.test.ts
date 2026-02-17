import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ThresholdMLDSA, Round1State, Round2State } from '../src/threshold-ml-dsa.ts';

describe('Threshold ML-DSA', () => {
  describe('Parameter validation', () => {
    should('reject T < 2', () => {
      throws(() => ThresholdMLDSA.getParams(1, 3, 44));
    });
    should('reject T > N', () => {
      throws(() => ThresholdMLDSA.getParams(4, 3, 44));
    });
    should('reject N > 6', () => {
      throws(() => ThresholdMLDSA.getParams(2, 7, 44));
    });
    should('reject N < 2', () => {
      throws(() => ThresholdMLDSA.getParams(2, 1, 44));
    });
    should('reject invalid security level', () => {
      throws(() => ThresholdMLDSA.getParams(2, 3, 99));
    });
    should('accept valid params', () => {
      const params = ThresholdMLDSA.getParams(2, 3, 44);
      eql(params.T, 2);
      eql(params.N, 3);
      eql(params.nu, 3.0);
      eql(typeof params.K_iter, 'number');
      eql(typeof params.r, 'number');
      eql(typeof params.rPrime, 'number');
    });
    should('normalize security levels (128->44, 192->65, 256->87)', () => {
      const p44a = ThresholdMLDSA.getParams(2, 3, 128);
      const p44b = ThresholdMLDSA.getParams(2, 3, 44);
      eql(p44a, p44b);

      const p65a = ThresholdMLDSA.getParams(2, 3, 192);
      const p65b = ThresholdMLDSA.getParams(2, 3, 65);
      eql(p65a, p65b);

      const p87a = ThresholdMLDSA.getParams(2, 3, 256);
      const p87b = ThresholdMLDSA.getParams(2, 3, 87);
      eql(p87a, p87b);
    });
    should('accept all valid (T,N) combos for ML-DSA-44', () => {
      for (let n = 2; n <= 6; n++) {
        for (let t = 2; t <= n; t++) {
          const params = ThresholdMLDSA.getParams(t, n, 44);
          eql(params.T, t);
          eql(params.N, n);
        }
      }
    });
    should('accept all valid (T,N) combos for ML-DSA-65', () => {
      for (let n = 2; n <= 6; n++) {
        for (let t = 2; t <= n; t++) {
          const params = ThresholdMLDSA.getParams(t, n, 65);
          eql(params.T, t);
          eql(params.N, n);
        }
      }
    });
    should('accept all valid (T,N) combos for ML-DSA-87', () => {
      for (let n = 2; n <= 6; n++) {
        for (let t = 2; t <= n; t++) {
          const params = ThresholdMLDSA.getParams(t, n, 87);
          eql(params.T, t);
          eql(params.N, n);
        }
      }
    });
  });

  describe('Key generation', () => {
    should('generate deterministic keys from seed', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 42;
      const r1 = th.keygen(seed.slice());
      const r2 = th.keygen(seed.slice());
      eql(r1.publicKey, r2.publicKey);
      eql(r1.shares.length, 3);
      eql(r2.shares.length, 3);
    });

    should('generate correct number of shares', () => {
      const th = ThresholdMLDSA.create(44, 3, 5);
      const { shares } = th.keygen();
      eql(shares.length, 5);
      for (let i = 0; i < 5; i++) {
        eql(shares[i].id, i);
        eql(shares[i].rho.length, 32);
        eql(shares[i].key.length, 32);
        eql(shares[i].tr.length, 64);
      }
    });

    should('generate random keys without seed', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const r1 = th.keygen();
      const r2 = th.keygen();
      eql(r1.publicKey.length, r2.publicKey.length);
      // Two random keygens should differ (probability of collision: negligible)
      let same = true;
      for (let i = 0; i < r1.publicKey.length; i++) {
        if (r1.publicKey[i] !== r2.publicKey[i]) {
          same = false;
          break;
        }
      }
      eql(same, false);
    });

    should('reject wrong seed length', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      throws(() => th.keygen(new Uint8Array(16)));
      throws(() => th.keygen(new Uint8Array(64)));
    });

    should('public key has correct length for ML-DSA-44', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey } = th.keygen();
      eql(publicKey.length, ml_dsa44.lengths.publicKey);
    });

    should('public key has correct length for ML-DSA-65', () => {
      const th = ThresholdMLDSA.create(65, 2, 3);
      const { publicKey } = th.keygen();
      eql(publicKey.length, ml_dsa65.lengths.publicKey);
    });

    should('public key has correct length for ML-DSA-87', () => {
      const th = ThresholdMLDSA.create(87, 2, 3);
      const { publicKey } = th.keygen();
      eql(publicKey.length, ml_dsa87.lengths.publicKey);
    });

    should('all shares have same rho and tr', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { shares } = th.keygen();
      for (let i = 1; i < shares.length; i++) {
        eql(shares[i].rho, shares[0].rho);
        eql(shares[i].tr, shares[0].tr);
      }
    });

    should('each share has unique key', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const { shares } = th.keygen();
      for (let i = 0; i < shares.length; i++) {
        for (let j = i + 1; j < shares.length; j++) {
          let same = true;
          for (let k = 0; k < 32; k++) {
            if (shares[i].key[k] !== shares[j].key[k]) {
              same = false;
              break;
            }
          }
          eql(same, false);
        }
      }
    });
  });

  describe('2-of-3 signing (ML-DSA-44)', () => {
    should('produce valid signature with parties 0,1', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 1;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3, 4]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('produce valid signature with parties 0,2', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 2;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([5, 6, 7, 8]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('produce valid signature with parties 1,2', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 3;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([9, 10, 11, 12]);

      const sig = th.sign(msg, publicKey, [shares[1], shares[2]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('2-of-2 signing (ML-DSA-44)', () => {
    should('produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 2, 2);
      const seed = new Uint8Array(32);
      seed[0] = 10;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('3-of-4 signing (ML-DSA-44)', () => {
    should('produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 3, 4);
      const seed = new Uint8Array(32);
      seed[0] = 20;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([10, 20, 30]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('T=N signing (ML-DSA-44)', () => {
    should('3-of-3 produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 3, 3);
      const seed = new Uint8Array(32);
      seed[0] = 30;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('4-of-4 produce valid signature', () => {
      const th = ThresholdMLDSA.create(44, 4, 4);
      const seed = new Uint8Array(32);
      seed[0] = 31;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([4, 5, 6]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2], shares[3]]);
      eql(sig.length, ml_dsa44.lengths.signature);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('All subsets produce valid signatures', () => {
    should('any 2-of-4 subset signs correctly', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const seed = new Uint8Array(32);
      seed[0] = 40;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([100, 200]);

      // All C(4,2) = 6 subsets
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
  });

  describe('Signing with context', () => {
    should('produce valid signature with context', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 50;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3, 4]);
      const ctx = new Uint8Array([10, 20, 30]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]], { context: ctx });
      eql(sig.length, ml_dsa44.lengths.signature);
      // Verify with same context
      eql(ml_dsa44.verify(sig, msg, publicKey, { context: ctx }), true);
    });

    should('signature with context fails verification without context', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 51;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3, 4]);
      const ctx = new Uint8Array([10, 20, 30]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]], { context: ctx });
      // Verify without context should fail
      eql(ml_dsa44.verify(sig, msg, publicKey), false);
    });

    should('signature with context fails verification with wrong context', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 52;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3, 4]);
      const ctx = new Uint8Array([10, 20, 30]);
      const wrongCtx = new Uint8Array([99, 99, 99]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]], { context: ctx });
      eql(ml_dsa44.verify(sig, msg, publicKey, { context: wrongCtx }), false);
    });
  });

  describe('ML-DSA-65 signing', () => {
    should('2-of-3 produce valid signature', () => {
      const th = ThresholdMLDSA.create(65, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 60;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa65.lengths.signature);
      eql(ml_dsa65.verify(sig, msg, publicKey), true);
    });

    should('2-of-2 produce valid signature', () => {
      const th = ThresholdMLDSA.create(65, 2, 2);
      const seed = new Uint8Array(32);
      seed[0] = 61;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([4, 5, 6]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa65.lengths.signature);
      eql(ml_dsa65.verify(sig, msg, publicKey), true);
    });
  });

  describe('ML-DSA-87 signing', () => {
    should('2-of-3 produce valid signature', () => {
      const th = ThresholdMLDSA.create(87, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 70;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa87.lengths.signature);
      eql(ml_dsa87.verify(sig, msg, publicKey), true);
    });

    should('2-of-2 produce valid signature', () => {
      const th = ThresholdMLDSA.create(87, 2, 2);
      const seed = new Uint8Array(32);
      seed[0] = 71;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([4, 5, 6]);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(sig.length, ml_dsa87.lengths.signature);
      eql(ml_dsa87.verify(sig, msg, publicKey), true);
    });
  });

  describe('create() with NIST security levels', () => {
    should('create with level 128 (= ML-DSA-44)', () => {
      const th = ThresholdMLDSA.create(128, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 80;
      const { publicKey, shares } = th.keygen(seed);
      eql(publicKey.length, ml_dsa44.lengths.publicKey);

      const msg = new Uint8Array([1, 2]);
      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('create with level 192 (= ML-DSA-65)', () => {
      const th = ThresholdMLDSA.create(192, 2, 3);
      const { publicKey } = th.keygen();
      eql(publicKey.length, ml_dsa65.lengths.publicKey);
    });

    should('create with level 256 (= ML-DSA-87)', () => {
      const th = ThresholdMLDSA.create(256, 2, 3);
      const { publicKey } = th.keygen();
      eql(publicKey.length, ml_dsa87.lengths.publicKey);
    });
  });

  describe('Error cases', () => {
    should('fail with insufficient shares', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = th.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      throws(() => th.sign(msg, publicKey, [shares[0]]));
    });

    should('fail with wrong publicKey length', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      throws(() => th.sign(msg, new Uint8Array(10), [shares[0], shares[1]]));
    });

    should('fail with empty publicKey', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      throws(() => th.sign(msg, new Uint8Array(0), [shares[0], shares[1]]));
    });

    should('reject wrong seed length in keygen', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      throws(() => th.keygen(new Uint8Array(16)));
      throws(() => th.keygen(new Uint8Array(64)));
    });

    should('reject duplicate share IDs', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { publicKey, shares } = th.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      // Pass the same share twice (same ID)
      throws(() => th.sign(msg, publicKey, [shares[0], shares[0]]));
    });
  });

  describe('Empty and edge-case messages', () => {
    should('sign empty message', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 90;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array(0);

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });

    should('sign large message', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 91;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array(1024);
      for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;

      const sig = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('Superset of shares', () => {
    should('use only first T shares when given more', () => {
      const th = ThresholdMLDSA.create(44, 2, 4);
      const seed = new Uint8Array(32);
      seed[0] = 95;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3]);

      // Providing all 4 shares to a 2-of-4 scheme should work (uses first 2)
      const sig = th.sign(msg, publicKey, [shares[0], shares[1], shares[2], shares[3]]);
      eql(ml_dsa44.verify(sig, msg, publicKey), true);
    });
  });

  describe('Distributed signing protocol', () => {
    should('produce valid signature via round1→round2→round3→combine (2-of-3)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 200;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([10, 20, 30]);
      const activePartyIds = [0, 1];

      let sig: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        // Round 1: each party independently
        const r1_0 = th.round1(shares[0], { nonce: attempt });
        const r1_1 = th.round1(shares[1], { nonce: attempt });

        // Round 2: exchange hashes, get commitments
        const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
        const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
        const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);

        // Round 3: exchange commitments, compute responses
        const allCommitments = [r2_0.commitment, r2_1.commitment];
        const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
        const resp_1 = th.round3(shares[1], allCommitments, r1_1.state, r2_1.state);

        // Combine
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

    should('produce valid signature via distributed protocol (2-of-3, parties 0,2)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 201;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1, 2, 3, 4, 5]);
      const activePartyIds = [0, 2];

      let sig: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        const r1_0 = th.round1(shares[0], { nonce: attempt });
        const r1_2 = th.round1(shares[2], { nonce: attempt });

        const allHashes = [r1_0.commitmentHash, r1_2.commitmentHash];
        const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
        const r2_2 = th.round2(shares[2], activePartyIds, msg, allHashes, r1_2.state);

        const allCommitments = [r2_0.commitment, r2_2.commitment];
        const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
        const resp_2 = th.round3(shares[2], allCommitments, r1_2.state, r2_2.state);

        sig = th.combine(publicKey, msg, allCommitments, [resp_0, resp_2]);
        r1_0.state.destroy();
        r1_2.state.destroy();
        r2_0.state.destroy();
        r2_2.state.destroy();
        if (sig !== null) break;
      }

      eql(sig !== null, true);
      eql(ml_dsa44.verify(sig!, msg, publicKey), true);
    });

    should('produce valid signature with context via distributed protocol', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 202;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([99]);
      const ctx = new Uint8Array([0xde, 0xad]);
      const activePartyIds = [0, 1];

      let sig: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        const r1_0 = th.round1(shares[0], { nonce: attempt });
        const r1_1 = th.round1(shares[1], { nonce: attempt });

        const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
        const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state, { context: ctx });
        const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state, { context: ctx });

        const allCommitments = [r2_0.commitment, r2_1.commitment];
        const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
        const resp_1 = th.round3(shares[1], allCommitments, r1_1.state, r2_1.state);

        sig = th.combine(publicKey, msg, allCommitments, [resp_0, resp_1], { context: ctx });
        r1_0.state.destroy();
        r1_1.state.destroy();
        r2_0.state.destroy();
        r2_1.state.destroy();
        if (sig !== null) break;
      }

      eql(sig !== null, true);
      // Verify with context
      eql(ml_dsa44.verify(sig!, msg, publicKey, { context: ctx }), true);
      // Verify without context fails
      eql(ml_dsa44.verify(sig!, msg, publicKey), false);
    });

    should('commitment byte length matches actual commitment', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      eql(r1.state._commitment.length, th.commitmentByteLength);
      r1.state.destroy();
    });

    should('response byte length matches actual response', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 203;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([1]);
      const activePartyIds = [0, 1];

      const r1_0 = th.round1(shares[0]);
      const r1_1 = th.round1(shares[1]);
      const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
      const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
      const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);
      const allCommitments = [r2_0.commitment, r2_1.commitment];
      const resp = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);

      eql(resp.length, th.responseByteLength);
      r1_0.state.destroy();
      r1_1.state.destroy();
      r2_0.state.destroy();
      r2_1.state.destroy();
    });

    should('commitment hash is 32 bytes', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      eql(r1.commitmentHash.length, 32);
      r1.state.destroy();
    });

    should('Round1State.destroy() prevents reuse', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      r1.state.destroy();
      throws(() => r1.state._commitment, /destroyed/);
      throws(() => r1.state._stws, /destroyed/);
    });

    should('Round2State.destroy() prevents reuse', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const msg = new Uint8Array([1]);
      const r1 = th.round1(shares[0]);
      const r2 = th.round2(shares[0], [0, 1], msg, [r1.commitmentHash, r1.commitmentHash], r1.state);
      r2.state.destroy();
      throws(() => r2.state._mu, /destroyed/);
      throws(() => r2.state._hashes, /destroyed/);
      r1.state.destroy();
    });

    should('round3 rejects tampered commitment (hash mismatch)', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 204;
      const { shares } = th.keygen(seed);
      const msg = new Uint8Array([1]);
      const activePartyIds = [0, 1];

      const r1_0 = th.round1(shares[0]);
      const r1_1 = th.round1(shares[1]);
      const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
      const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
      const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);

      // Tamper with party 1's commitment
      const tampered = r2_1.commitment.slice();
      tampered[0] ^= 0xff;

      throws(
        () => th.round3(shares[0], [r2_0.commitment, tampered], r1_0.state, r2_0.state),
        /Commitment hash mismatch for party 1/
      );
      r1_0.state.destroy();
      r1_1.state.destroy();
      r2_0.state.destroy();
      r2_1.state.destroy();
    });

    should('round2 rejects wrong number of hashes', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      throws(
        () => th.round2(shares[0], [0, 1], new Uint8Array([1]), [r1.commitmentHash], r1.state),
        /Expected 2 hashes, got 1/
      );
      r1.state.destroy();
    });

    should('round2 rejects insufficient parties', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      throws(
        () => th.round2(shares[0], [0], new Uint8Array([1]), [r1.commitmentHash], r1.state),
        /Need at least 2 parties/
      );
      r1.state.destroy();
    });

    should('round2 rejects duplicate party IDs', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const { shares } = th.keygen();
      const r1 = th.round1(shares[0]);
      throws(
        () =>
          th.round2(
            shares[0],
            [0, 0],
            new Uint8Array([1]),
            [r1.commitmentHash, r1.commitmentHash],
            r1.state
          ),
        /Duplicate party ID/
      );
      r1.state.destroy();
    });

    should('distributed protocol works with ML-DSA-65', () => {
      const th = ThresholdMLDSA.create(65, 2, 2);
      const seed = new Uint8Array(32);
      seed[0] = 205;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([42]);
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
      eql(ml_dsa65.verify(sig!, msg, publicKey), true);
    });

    should('distributed and local sign produce valid but independent signatures', () => {
      const th = ThresholdMLDSA.create(44, 2, 3);
      const seed = new Uint8Array(32);
      seed[0] = 206;
      const { publicKey, shares } = th.keygen(seed);
      const msg = new Uint8Array([7, 8, 9]);

      // Local sign
      const sigLocal = th.sign(msg, publicKey, [shares[0], shares[1]]);
      eql(ml_dsa44.verify(sigLocal, msg, publicKey), true);

      // Distributed sign
      const activePartyIds = [0, 1];
      let sigDistributed: Uint8Array | null = null;
      for (let attempt = 0; attempt < 500; attempt++) {
        const r1_0 = th.round1(shares[0], { nonce: attempt });
        const r1_1 = th.round1(shares[1], { nonce: attempt });
        const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
        const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
        const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);
        const allCommitments = [r2_0.commitment, r2_1.commitment];
        const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
        const resp_1 = th.round3(shares[1], allCommitments, r1_1.state, r2_1.state);
        sigDistributed = th.combine(publicKey, msg, allCommitments, [resp_0, resp_1]);
        r1_0.state.destroy();
        r1_1.state.destroy();
        r2_0.state.destroy();
        r2_1.state.destroy();
        if (sigDistributed !== null) break;
      }

      eql(sigDistributed !== null, true);
      eql(ml_dsa44.verify(sigDistributed!, msg, publicKey), true);

      // Both produce valid signatures (but different due to randomness)
      eql(sigLocal.length, sigDistributed!.length);
    });
  });
});

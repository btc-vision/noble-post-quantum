/**
 * ML-DSA: Module Lattice-based Digital Signature Algorithm from
 * [FIPS-204](https://csrc.nist.gov/pubs/fips/204/ipd). A.k.a. CRYSTALS-Dilithium.
 *
 * Has similar internals to ML-KEM, but their keys and params are different.
 * Check out [official site](https://www.pq-crystals.org/dilithium/index.shtml),
 * [repo](https://github.com/pq-crystals/dilithium).
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { abool } from '@noble/curves/utils.js';
import { shake256 } from '@noble/hashes/sha3.js';
import type { CHash } from '@noble/hashes/utils.js';
import { type XOF, XOF128, XOF256 } from './_crystals.ts';
import {
  createMLDSAPrimitives,
  type MLDSAPrimitives,
  type PrimitivesOpts,
  D,
  GAMMA2_1,
  GAMMA2_2,
  N,
  Q,
} from './ml-dsa-primitives.ts';
import {
  abytes,
  type BytesCoderLen,
  checkHash,
  cleanBytes,
  type CryptoKeys,
  equalBytes,
  getMessage,
  getMessagePrehash,
  randomBytes,
  type Signer,
  type SigOpts,
  splitCoder,
  validateOpts,
  validateSigOpts,
  validateVerOpts,
  type VerOpts,
} from './utils.ts';

export type DSAInternalOpts = { externalMu?: boolean };
function validateInternalOpts(opts: DSAInternalOpts) {
  validateOpts(opts);
  if (opts.externalMu !== undefined) abool(opts.externalMu, 'opts.externalMu');
}

/** Signer API, containing internal methods */
export type DSAInternal = CryptoKeys & {
  lengths: Signer['lengths'];
  sign: (msg: Uint8Array, secretKey: Uint8Array, opts?: SigOpts & DSAInternalOpts) => Uint8Array;
  verify: (
    sig: Uint8Array,
    msg: Uint8Array,
    pubKey: Uint8Array,
    opts?: VerOpts & DSAInternalOpts
  ) => boolean;
};
export type DSA = Signer & { internal: DSAInternal; primitives: MLDSAPrimitives };

/** Various lattice params. */
export type DSAParam = {
  K: number;
  L: number;
  D: number;
  GAMMA1: number;
  GAMMA2: number;
  TAU: number;
  ETA: number;
  OMEGA: number;
};
/** Internal params for different versions of ML-DSA  */
// prettier-ignore
export const PARAMS: Record<string, DSAParam> = {
  2: { K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80 },
  3: { K: 6, L: 5, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 49, ETA: 4, OMEGA: 55 },
  5: { K: 8, L: 7, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 60, ETA: 2, OMEGA: 75 },
} as const;

type DilithiumOpts = PrimitivesOpts & {
  securityLevel: number;
};

function getDilithium(opts: DilithiumOpts) {
  const p = createMLDSAPrimitives(opts);
  const { K, L, GAMMA1, GAMMA2, BETA, OMEGA } = p;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128, XOF256 } = p;
  const {
    mod,
    smod,
    newPoly,
    NTT,
    polyAdd,
    polySub,
    polyShiftl,
    polyChknorm,
    MultiplyNTTs,
    RejNTTPoly,
    HighBits,
    LowBits,
    SampleInBall,
    RejBoundedPoly,
    polyPowerRound,
    polyUseHint,
    polyMakeHint,
    W1Vec,
    ZCoder,
    publicCoder,
    secretCoder,
    sigCoder,
  } = p;

  const signRandBytes = 32;
  const seedCoder = splitCoder('seed', 32, 64, 32);
  // API & argument positions are exactly as in FIPS204.
  const internal: DSAInternal = {
    info: { type: 'internal-ml-dsa' },
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      seed: 32,
      signature: sigCoder.bytesLen,
      signRand: signRandBytes,
    },
    keygen: (seed?: Uint8Array) => {
      // H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128) 2: ▷ expand seed
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === undefined;
      if (randSeed) seed = randomBytes(32);
      abytes(seed!, 32, 'seed');
      seedDst.set(seed!);
      if (randSeed) cleanBytes(seed!);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(
        shake256(seedDst, { dkLen: seedCoder.bytesLen })
      );
      const xofPrime = XOF256(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++) s1.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
      const s1Hat = s1.map((i) => NTT.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF128(rho);
      const t = newPoly(N);
      for (let i = 0; i < K; i++) {
        // t ← NTT−1(A*NTT(s1)) + s2
        cleanBytes(t); // don't-reallocate
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // super slow!
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i])); // (t1, t0) ← Power2Round(t, d)
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]); // pk ← pkEncode(ρ, t1)
      const tr = shake256(publicKey, { dkLen: TR_BYTES }); // tr ← H(BytesToBits(pk), 512)
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]); // sk ← skEncode(ρ, K,tr, s1, s2, t0)
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return { publicKey, secretKey };
    },
    getPublicKey: (secretKey: Uint8Array) => {
      const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey); // (ρ, K,tr, s1, s2, t0) ← skDecode(sk)
      const xof = XOF128(rho);
      const s1Hat = s1.map((p) => NTT.encode(p.slice()));
      const t1: Int32Array[] = [];
      const tmp = newPoly(N);
      for (let i = 0; i < K; i++) {
        tmp.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // A_ij in NTT
          polyAdd(tmp, MultiplyNTTs(aij, s1Hat[j])); // += A_ij * s1_j
        }
        NTT.decode(tmp); // NTT⁻¹
        polyAdd(tmp, s2[i]); // t_i = A·s1 + s2
        const { r1 } = polyPowerRound(tmp); // r1 = t1, r0 ≈ t0
        t1.push(r1);
      }
      xof.clean();
      cleanBytes(tmp, s1Hat, _t0, s1, s2);
      return publicCoder.encode([rho, t1]);
    },
    // NOTE: random is optional.
    sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts & DSAInternalOpts = {}) => {
      validateSigOpts(opts);
      validateInternalOpts(opts);
      let { extraEntropy: random, externalMu = false } = opts;
      // This part can be pre-cached per secretKey, but there is only minor performance improvement,
      // since we re-use a lot of variables to computation.
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey); // (ρ, K,tr, s1, s2, t0) ← skDecode(sk)
      // Cache matrix to avoid re-compute later
      const A: Int32Array[][] = []; // A ← ExpandA(ρ)
      const xof = XOF128(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++) pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++) NTT.encode(s1[i]); // sˆ1 ← NTT(s1)
      for (let i = 0; i < K; i++) {
        NTT.encode(s2[i]); // sˆ2 ← NTT(s2)
        NTT.encode(t0[i]); // tˆ0 ← NTT(t0)
      }
      // This part is per msg
      const mu = externalMu
        ? msg
        : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest(); // 6: µ ← H(tr||M, 512) ▷ Compute message representative µ

      // Compute private random seed
      const rnd =
        random === false
          ? new Uint8Array(32)
          : random === undefined
            ? randomBytes(signRandBytes)
            : random;
      abytes(rnd, 32, 'extraEntropy');
      const rhoprime = shake256
        .create({ dkLen: CRH_BYTES })
        .update(_K)
        .update(rnd)
        .update(mu)
        .digest(); // ρ′← H(K||rnd||µ, 512)

      abytes(rhoprime, CRH_BYTES);
      const x256 = XOF256(rhoprime, ZCoder.bytesLen);
      //  Rejection sampling loop
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        // y ← ExpandMask(ρ , κ)
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 0xff, kappa >> 8)()));
        const z = y.map((i) => NTT.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          // w ← NTT−1(A ◦ NTT(y))
          const wi = newPoly(N);
          for (let j = 0; j < L; j++) polyAdd(wi, MultiplyNTTs(A[i][j], z[j]));
          NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits)); // w1 ← HighBits(w)
        // Commitment hash: c˜ ∈{0, 1 2λ } ← H(µ||w1Encode(w1), 2λ)
        const cTilde = shake256
          .create({ dkLen: C_TILDE_BYTES })
          .update(mu)
          .update(W1Vec.encode(w1))
          .digest();
        // Verifer's challenge
        const cHat = NTT.encode(SampleInBall(cTilde)); // c ← SampleInBall(c˜1); cˆ ← NTT(c)
        // ⟨⟨cs1⟩⟩ ← NTT−1(cˆ◦ sˆ1)
        const cs1 = s1.map((i) => MultiplyNTTs(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd(NTT.decode(cs1[i]), y[i]); // z ← y + ⟨⟨cs1⟩⟩
          if (polyChknorm(cs1[i], GAMMA1 - BETA)) continue main_loop; // ||z||∞ ≥ γ1 − β
        }
        // cs1 is now z (▷ Signer's response)
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = NTT.decode(MultiplyNTTs(s2[i], cHat)); // ⟨⟨cs2⟩⟩ ← NTT−1(cˆ◦ sˆ2)
          const r0 = polySub(w[i], cs2).map(LowBits); // r0 ← LowBits(w − ⟨⟨cs2⟩⟩)
          if (polyChknorm(r0, GAMMA2 - BETA)) continue main_loop; // ||r0||∞ ≥ γ2 − β
          const ct0 = NTT.decode(MultiplyNTTs(t0[i], cHat)); // ⟨⟨ct0⟩⟩ ← NTT−1(cˆ◦ tˆ0)
          if (polyChknorm(ct0, GAMMA2)) continue main_loop;
          polyAdd(r0, ct0);
          // ▷ Signer's hint
          const hint = polyMakeHint(r0, w1[i]); // h ← MakeHint(−⟨⟨ct0⟩⟩, w− ⟨⟨cs2⟩⟩ + ⟨⟨ct0⟩⟩)
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA) continue; // the number of 1's in h is greater than ω
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]); // σ ← sigEncode(c˜, z mod±q, h)
        // rho, _K, tr is subarray of secretKey, cannot clean.
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, mu, s1, s2, t0, ...A);
        return res;
      }
      // @ts-ignore
      throw new Error('Unreachable code path reached, report this error');
    },
    verify: (
      sig: Uint8Array,
      msg: Uint8Array,
      publicKey: Uint8Array,
      opts: DSAInternalOpts = {}
    ) => {
      validateInternalOpts(opts);
      const { externalMu = false } = opts;
      // ML-DSA.Verify(pk, M, σ): Verifes a signature σ for a message M.
      const [rho, t1] = publicCoder.decode(publicKey); // (ρ, t1) ← pkDecode(pk)
      const tr = shake256(publicKey, { dkLen: TR_BYTES }); // 6: tr ← H(BytesToBits(pk), 512)

      if (sig.length !== sigCoder.bytesLen) return false; // return false instead of exception
      const [cTilde, z, h] = sigCoder.decode(sig); // (c˜, z, h) ← sigDecode(σ), ▷ Signer's commitment hash c ˜, response z and hint
      if (h === false) return false; // if h = ⊥ then return false
      for (let i = 0; i < L; i++) if (polyChknorm(z[i], GAMMA1 - BETA)) return false;
      const mu = externalMu
        ? msg
        : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest(); // 7: µ ← H(tr||M, 512)
      // Compute verifer's challenge from c˜
      const c = NTT.encode(SampleInBall(cTilde)); // c ← SampleInBall(c˜1)
      const zNtt = z.map((i) => i.slice()); // zNtt = NTT(z)
      for (let i = 0; i < L; i++) NTT.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF128(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs(NTT.encode(polyShiftl(t1[i])), c); //c * t1 * (2**d)
        const Az = newPoly(N); // // A * z
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // A[i][j] inplace
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        // wApprox = A*z - c*t1 * (2**d)
        const wApprox = NTT.decode(polySub(Az, ct12d));
        // Reconstruction of signer's commitment
        wTick1.push(polyUseHint(wApprox, h[i])); // w ′ ← UseHint(h, w'approx )
      }
      xof.clean();
      // c˜′← H (µ||w1Encode(w′1), 2λ),  Hash it; this should match c˜
      const c2 = shake256
        .create({ dkLen: C_TILDE_BYTES })
        .update(mu)
        .update(W1Vec.encode(wTick1))
        .digest();
      // Additional checks in FIPS-204:
      // [[ ||z||∞ < γ1 − β ]] and [[c ˜ = c˜′]] and [[number of 1's in h is ≤ ω]]
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA)) return false;
      }
      for (const t of z) if (polyChknorm(t, GAMMA1 - BETA)) return false;
      return equalBytes(cTilde, c2);
    },
  };
  return {
    info: { type: 'ml-dsa' },
    internal,
    primitives: p,
    securityLevel: opts.securityLevel,
    keygen: internal.keygen,
    lengths: internal.lengths,
    getPublicKey: internal.getPublicKey,
    sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
      validateSigOpts(opts);
      const M = getMessage(msg, opts.context);
      const res = internal.sign(M, secretKey, opts);
      cleanBytes(M);
      return res;
    },
    verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
      validateVerOpts(opts);
      return internal.verify(sig, getMessage(msg, opts.context), publicKey);
    },
    prehash: (hash: CHash) => {
      checkHash(hash, opts.securityLevel);
      return {
        info: { type: 'hashml-dsa' },
        securityLevel: opts.securityLevel,
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
          validateSigOpts(opts);
          const M = getMessagePrehash(hash, msg, opts.context);
          const res = internal.sign(M, secretKey, opts);
          cleanBytes(M);
          return res;
        },
        verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
          validateVerOpts(opts);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts.context), publicKey);
        },
      };
    },
  };
}

/** ML-DSA-44 for 128-bit security level. Not recommended after 2030, as per ASD. */
export const ml_dsa44: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256,
  securityLevel: 128,
});

/** ML-DSA-65 for 192-bit security level. Not recommended after 2030, as per ASD. */
export const ml_dsa65: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256,
  securityLevel: 192,
});

/** ML-DSA-87 for 256-bit security level. OK after 2030, as per ASD. */
export const ml_dsa87: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256,
  securityLevel: 256,
});

/**
 * ML-DSA ring arithmetic, encoding, and sampling primitives.
 * Extracted from getDilithium to enable reuse by threshold signing.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { shake256 } from '@noble/hashes/sha3.js';
import { genCrystals, type XOF } from './_crystals.ts';
import {
  type BytesCoderLen,
  cleanBytes,
  splitCoder,
  vecCoder,
} from './utils.ts';

// ==================== Constants ====================
export const N = 256;
// 2**23 − 2**13 + 1, 23 bits: multiply will be 46. We have enough precision in JS to avoid bigints
export const Q = 8380417;
const ROOT_OF_UNITY = 1753;
// f = 256**−1 mod q, pow(256, -1, q) = 8347681 (python3)
const F = 8347681;
export const D = 13;
// Dilithium is kinda parametrized over GAMMA2, but everything will break with any other value.
export const GAMMA2_1: number = Math.floor((Q - 1) / 88) | 0;
export const GAMMA2_2: number = Math.floor((Q - 1) / 32) | 0;

// ==================== Core NTT/Ring ====================
// NOTE: there is a lot cases where negative numbers used (with smod instead of mod).
type Poly = Int32Array;
const newPoly = (n: number): Int32Array => new Int32Array(n);

const { mod, smod, NTT, bitsCoder } = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8,
});

// ==================== Ring Arithmetic ====================
const polyAdd = (a: Poly, b: Poly): Poly => {
  for (let i = 0; i < a.length; i++) a[i] = mod(a[i] + b[i]);
  return a;
};
const polySub = (a: Poly, b: Poly): Poly => {
  for (let i = 0; i < a.length; i++) a[i] = mod(a[i] - b[i]);
  return a;
};

const polyShiftl = (p: Poly): Poly => {
  for (let i = 0; i < N; i++) p[i] <<= D;
  return p;
};

const polyChknorm = (p: Poly, B: number): boolean => {
  // Not very sure about this, but FIPS204 doesn't provide any function for that :(
  for (let i = 0; i < N; i++) if (Math.abs(smod(p[i])) >= B) return true;
  return false;
};

const MultiplyNTTs = (a: Poly, b: Poly): Poly => {
  // NOTE: we don't use montgomery reduction in code, since it requires 64 bit ints,
  // which is not available in JS. mod(a[i] * b[i]) is ok, since Q is 23 bit,
  // which means a[i] * b[i] is 46 bit, which is safe to use in JS. (number is 53 bits).
  // Barrett reduction is slower than mod :(
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++) c[i] = mod(a[i] * b[i]);
  return c;
};

// ==================== Sampling ====================
type XofGet = ReturnType<ReturnType<XOF>['get']>;

// Return poly in NTT representation
function RejNTTPoly(xof: XofGet): Int32Array {
  // Samples a polynomial ∈ Tq.
  const r = newPoly(N);
  // NOTE: we can represent 3xu24 as 4xu32, but it doesn't improve perf :(
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3) throw new Error('RejNTTPoly: unaligned block');
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | (b[i + 1] << 8) | (b[i + 2] << 16)) & 0x7fffff; // 3 bytes
      if (t < Q) r[j++] = t;
    }
  }
  return r;
}

// ==================== Coder Helper ====================
const id = <T>(n: T): T => n;
type IdNum = (n: number) => number;

const polyCoder = (d: number, compress: IdNum = id, verify: IdNum = id) =>
  bitsCoder(d, {
    encode: (i: number) => compress(verify(i)),
    decode: (i: number) => verify(compress(i)),
  });

// ==================== Parameterized Primitives Factory ====================
export type PrimitivesOpts = {
  K: number;
  L: number;
  GAMMA1: number;
  GAMMA2: number;
  TAU: number;
  ETA: number;
  OMEGA: number;
  C_TILDE_BYTES: number;
  CRH_BYTES: number;
  TR_BYTES: number;
  XOF128: XOF;
  XOF256: XOF;
};

/** All ML-DSA primitives returned by createMLDSAPrimitives. */
export interface MLDSAPrimitives {
  // Constants
  readonly K: number;
  readonly L: number;
  readonly N: number;
  readonly Q: number;
  readonly D: number;
  readonly GAMMA1: number;
  readonly GAMMA2: number;
  readonly TAU: number;
  readonly ETA: number;
  readonly OMEGA: number;
  readonly BETA: number;
  readonly C_TILDE_BYTES: number;
  readonly CRH_BYTES: number;
  readonly TR_BYTES: number;
  readonly GAMMA2_1: number;
  readonly GAMMA2_2: number;
  // Ring arithmetic
  readonly mod: (a: number, modulo?: number) => number;
  readonly smod: (a: number, modulo?: number) => number;
  readonly newPoly: (n: number) => Int32Array;
  readonly polyAdd: (a: Int32Array, b: Int32Array) => Int32Array;
  readonly polySub: (a: Int32Array, b: Int32Array) => Int32Array;
  readonly polyShiftl: (p: Int32Array) => Int32Array;
  readonly polyChknorm: (p: Int32Array, B: number) => boolean;
  readonly MultiplyNTTs: (a: Int32Array, b: Int32Array) => Int32Array;
  readonly NTT: {
    readonly encode: (r: Int32Array) => Int32Array;
    readonly decode: (r: Int32Array) => Int32Array;
  };
  readonly RejNTTPoly: (xof: () => Uint8Array) => Int32Array;
  readonly XOF128: XOF;
  readonly XOF256: XOF;
  readonly cleanBytes: typeof cleanBytes;
  // Decomposition
  readonly decompose: (r: number) => { r1: number; r0: number };
  readonly HighBits: (r: number) => number;
  readonly LowBits: (r: number) => number;
  readonly MakeHint: (z: number, r: number) => number;
  readonly UseHint: (h: number, r: number) => number;
  readonly Power2Round: (r: number) => { r1: number; r0: number };
  // Poly-level helpers
  readonly polyPowerRound: (p: Int32Array) => { r0: Int32Array; r1: Int32Array };
  readonly polyUseHint: (u: Int32Array, h: Int32Array) => Int32Array;
  readonly polyMakeHint: (a: Int32Array, b: Int32Array) => { v: Int32Array; cnt: number };
  // Sampling
  readonly RejBoundedPoly: (xof: () => Uint8Array) => Int32Array;
  readonly SampleInBall: (seed: Uint8Array) => Int32Array;
  // Coders
  readonly ETACoder: BytesCoderLen<Int32Array>;
  readonly T0Coder: BytesCoderLen<Int32Array>;
  readonly T1Coder: BytesCoderLen<Int32Array>;
  readonly ZCoder: BytesCoderLen<Int32Array>;
  readonly W1Coder: BytesCoderLen<Int32Array>;
  readonly W1Vec: BytesCoderLen<Int32Array[]>;
  readonly hintCoder: BytesCoderLen<Int32Array[] | false>;
  readonly sigCoder: BytesCoderLen<[Uint8Array, Int32Array[], Int32Array[] | false]>;
  readonly publicCoder: BytesCoderLen<[Uint8Array, Int32Array[]]>;
  readonly secretCoder: BytesCoderLen<
    [Uint8Array, Uint8Array, Uint8Array, Int32Array[], Int32Array[], Int32Array[]]
  >;
}

export function createMLDSAPrimitives(opts: PrimitivesOpts): MLDSAPrimitives {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: _XOF128, XOF256: _XOF256 } = opts;

  if (![2, 4].includes(ETA)) throw new Error('Wrong ETA');
  if (![1 << 17, 1 << 19].includes(GAMMA1)) throw new Error('Wrong GAMMA1');
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2)) throw new Error('Wrong GAMMA2');
  const BETA = TAU * ETA;

  const decompose = (r: number) => {
    // Decomposes r into (r1, r0) such that r ≡ r1(2γ2) + r0 mod q.
    const rPlus = mod(r);
    const r0 = smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1) return { r1: 0 | 0, r0: (r0 - 1) | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 }; // r1 = HighBits, r0 = LowBits
  };

  const HighBits = (r: number) => decompose(r).r1;
  const LowBits = (r: number) => decompose(r).r0;
  const MakeHint = (z: number, r: number) => {
    // Compute hint bit indicating whether adding z to r alters the high bits of r.
    // From dilithium code
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || (z === Q - GAMMA2 && r === 0) ? 0 : 1;
    return res0;
  };

  const UseHint = (h: number, r: number) => {
    // Returns the high bits of r adjusted according to hint h
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1) return r0 > 0 ? mod(r1 + 1, m) | 0 : mod(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r: number) => {
    // Decomposes r into (r1, r0) such that r ≡ r1*(2**d) + r0 mod q.
    const rPlus = mod(r);
    const r0 = smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };

  const hintCoder: BytesCoderLen<Poly[] | false> = {
    bytesLen: OMEGA + K,
    encode: (h: Poly[] | false) => {
      if (h === false) throw new Error('hint.encode: hint is false'); // should never happen
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N; j++) if (h[i][j] !== 0) res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf: Uint8Array) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA) return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1]) return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++) if (buf[j] !== 0) return false;
      return h;
    },
  };

  const ETACoder = polyCoder(
    ETA === 2 ? 3 : 4,
    (i: number) => ETA - i,
    (i: number) => {
      if (!(-ETA <= i && i <= ETA))
        throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
      return i;
    }
  );
  const T0Coder = polyCoder(13, (i: number) => (1 << (D - 1)) - i);
  const T1Coder = polyCoder(10);
  // Requires smod. Need to fix!
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i: number) => smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  // Main structures
  const publicCoder = splitCoder('publicKey', 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder(
    'secretKey',
    32,
    32,
    TR_BYTES,
    vecCoder(ETACoder, L),
    vecCoder(ETACoder, K),
    vecCoder(T0Coder, K)
  );
  const sigCoder = splitCoder('signature', C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte =
    ETA === 2
      ? (n: number) => (n < 15 ? 2 - (n % 5) : false)
      : (n: number) => (n < 9 ? 4 - n : false);

  // Return poly in NTT representation
  function RejBoundedPoly(xof: XofGet) {
    // Samples an element a ∈ Rq with coeffcients in [−η, η] computed via rejection sampling from ρ.
    const r: Poly = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i = 0; j < N && i < b.length; i += 1) {
        // half byte. Should be superfast with vector instructions. But very slow with js :(
        const d1 = CoefFromHalfByte(b[i] & 0x0f);
        const d2 = CoefFromHalfByte((b[i] >> 4) & 0x0f);
        if (d1 !== false) r[j++] = d1;
        if (j < N && d2 !== false) r[j++] = d2;
      }
    }
    return r;
  }

  const SampleInBall = (seed: Uint8Array) => {
    // Samples a polynomial c ∈ Rq with coeffcients from {−1, 0, 1} and Hamming weight τ
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen) continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - (((masks[maskPos] >> maskBit++) & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };

  const polyPowerRound = (p: Poly) => {
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u: Poly, h: Poly): Poly => {
    for (let i = 0; i < N; i++) u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a: Poly, b: Poly) => {
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };

  return {
    // Constants
    K: K,
    L: L,
    N: N,
    Q: Q,
    D: D,
    GAMMA1: GAMMA1,
    GAMMA2: GAMMA2,
    TAU: TAU,
    ETA: ETA,
    OMEGA: OMEGA,
    BETA: BETA,
    C_TILDE_BYTES: C_TILDE_BYTES,
    CRH_BYTES: CRH_BYTES,
    TR_BYTES: TR_BYTES,
    GAMMA2_1: GAMMA2_1,
    GAMMA2_2: GAMMA2_2,
    // Ring arithmetic
    mod: mod,
    smod: smod,
    newPoly: newPoly,
    polyAdd: polyAdd,
    polySub: polySub,
    polyShiftl: polyShiftl,
    polyChknorm: polyChknorm,
    MultiplyNTTs: MultiplyNTTs,
    NTT: NTT,
    RejNTTPoly: RejNTTPoly,
    XOF128: _XOF128,
    XOF256: _XOF256,
    cleanBytes: cleanBytes,
    // Decomposition
    decompose: decompose,
    HighBits: HighBits,
    LowBits: LowBits,
    MakeHint: MakeHint,
    UseHint: UseHint,
    Power2Round: Power2Round,
    // Poly-level helpers
    polyPowerRound: polyPowerRound,
    polyUseHint: polyUseHint,
    polyMakeHint: polyMakeHint,
    // Sampling
    RejBoundedPoly: RejBoundedPoly,
    SampleInBall: SampleInBall,
    // Coders
    ETACoder: ETACoder,
    T0Coder: T0Coder,
    T1Coder: T1Coder,
    ZCoder: ZCoder,
    W1Coder: W1Coder,
    W1Vec: W1Vec,
    hintCoder: hintCoder,
    sigCoder: sigCoder,
    publicCoder: publicCoder,
    secretCoder: secretCoder,
  };
}

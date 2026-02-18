/**
 * ML-DSA ring arithmetic, encoding, and sampling primitives.
 * Extracted from getDilithium to enable reuse by threshold signing.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { shake256 } from '@noble/hashes/sha3.js';
import { genCrystals, type XOF } from './_crystals.ts';
import { type BytesCoderLen, cleanBytes, splitCoder, vecCoder } from './utils.ts';

/** Number of coefficients per polynomial ring element. */
export const N = 256;
/**
 * The prime modulus for ML-DSA ring arithmetic.
 * 2^23 - 2^13 + 1 = 8380417 (23 bits). Multiplication stays within 46 bits,
 * safely inside JS number precision (53 bits).
 */
export const Q = 8380417;
const ROOT_OF_UNITY = 1753;
/** f = 256^-1 mod q. */
const F = 8347681;
/** Number of dropped bits in Power2Round. */
export const D = 13;
/** GAMMA2 variant 1: floor((Q-1)/88). */
export const GAMMA2_1: number = Math.floor((Q - 1) / 88) | 0;
/** GAMMA2 variant 2: floor((Q-1)/32). */
export const GAMMA2_2: number = Math.floor((Q - 1) / 32) | 0;

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

/**
 * Add two polynomials element-wise (mod Q).
 * **Mutates `a` in place** and returns it.
 */
const polyAdd = (a: Poly, b: Poly): Poly => {
    for (let i = 0; i < a.length; i++) a[i] = mod(a[i] + b[i]);
    return a;
};

/**
 * Subtract polynomial `b` from `a` element-wise (mod Q).
 * **Mutates `a` in place** and returns it.
 */
const polySub = (a: Poly, b: Poly): Poly => {
    for (let i = 0; i < a.length; i++) a[i] = mod(a[i] - b[i]);
    return a;
};

/**
 * Left-shift each coefficient of `p` by D bits.
 * **Mutates `p` in place** and returns it.
 */
const polyShiftl = (p: Poly): Poly => {
    for (let i = 0; i < N; i++) p[i] <<= D;
    return p;
};

/** Check if any coefficient of `p` has |smod(coeff)| >= B. */
const polyChknorm = (p: Poly, B: number): boolean => {
    for (let i = 0; i < N; i++) if (Math.abs(smod(p[i])) >= B) return true;
    return false;
};

/**
 * Pointwise multiplication of two NTT-domain polynomials.
 * Returns a new polynomial (does not mutate inputs).
 */
const MultiplyNTTs = (a: Poly, b: Poly): Poly => {
    const c = newPoly(N);
    for (let i = 0; i < a.length; i++) c[i] = mod(a[i] * b[i]);
    return c;
};

type XofGet = ReturnType<ReturnType<XOF>['get']>;

/**
 * Sample a polynomial in NTT representation via rejection sampling (FIPS 204 Algorithm 14).
 */
function RejNTTPoly(xof: XofGet): Int32Array {
    const r = newPoly(N);
    for (let j = 0; j < N; ) {
        const b = xof();
        if (b.length % 3) throw new Error('RejNTTPoly: unaligned block');
        for (let i = 0; j < N && i <= b.length - 3; i += 3) {
            const t = (b[i + 0] | (b[i + 1] << 8) | (b[i + 2] << 16)) & 0x7fffff;
            if (t < Q) r[j++] = t;
        }
    }
    return r;
}

const id = <T>(n: T): T => n;
type IdNum = (n: number) => number;

const polyCoder = (d: number, compress: IdNum = id, verify: IdNum = id) =>
    bitsCoder(d, {
        encode: (i: number) => compress(verify(i)),
        decode: (i: number) => verify(compress(i)),
    });

/** Constructor options for {@link MLDSAPrimitives}. */
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

/**
 * ML-DSA ring arithmetic, encoding, and sampling primitives.
 *
 * Parameter-independent pure functions (polyAdd, polySub, etc.) are exposed
 * as public readonly properties so they can be destructured. Parameter-dependent
 * operations (decompose, HighBits, etc.) are proper class methods.
 */
export class MLDSAPrimitives {
    // --- Private fields ---
    readonly #coefFromHalfByte: (n: number) => number | false;

    // --- Public readonly constants ---
    public readonly K: number;
    public readonly L: number;
    public readonly N: number = N;
    public readonly Q: number = Q;
    public readonly D: number = D;
    public readonly GAMMA1: number;
    public readonly GAMMA2: number;
    public readonly TAU: number;
    public readonly ETA: number;
    public readonly OMEGA: number;
    public readonly BETA: number;
    public readonly C_TILDE_BYTES: number;
    public readonly CRH_BYTES: number;
    public readonly TR_BYTES: number;
    public readonly GAMMA2_1: number = GAMMA2_1;
    public readonly GAMMA2_2: number = GAMMA2_2;

    // --- Public readonly utilities (pure, parameter-independent) ---
    public readonly mod: (a: number, modulo?: number) => number = mod;
    public readonly smod: (a: number, modulo?: number) => number = smod;
    public readonly newPoly: (n: number) => Int32Array = newPoly;
    public readonly polyAdd: (a: Int32Array, b: Int32Array) => Int32Array = polyAdd;
    public readonly polySub: (a: Int32Array, b: Int32Array) => Int32Array = polySub;
    public readonly polyShiftl: (p: Int32Array) => Int32Array = polyShiftl;
    public readonly polyChknorm: (p: Int32Array, B: number) => boolean = polyChknorm;
    public readonly MultiplyNTTs: (a: Int32Array, b: Int32Array) => Int32Array = MultiplyNTTs;
    public readonly NTT: {
        readonly encode: (r: Int32Array) => Int32Array;
        readonly decode: (r: Int32Array) => Int32Array;
    } = NTT;
    public readonly RejNTTPoly: (xof: () => Uint8Array) => Int32Array = RejNTTPoly;
    public readonly XOF128: XOF;
    public readonly XOF256: XOF;
    public readonly cleanBytes: typeof cleanBytes = cleanBytes;

    // --- Public readonly coders (parameter-dependent, created in constructor) ---
    public readonly ETACoder: BytesCoderLen<Int32Array>;
    public readonly T0Coder: BytesCoderLen<Int32Array>;
    public readonly T1Coder: BytesCoderLen<Int32Array>;
    public readonly ZCoder: BytesCoderLen<Int32Array>;
    public readonly W1Coder: BytesCoderLen<Int32Array>;
    public readonly W1Vec: BytesCoderLen<Int32Array[]>;
    public readonly hintCoder: BytesCoderLen<Int32Array[] | false>;
    public readonly sigCoder: BytesCoderLen<[Uint8Array, Int32Array[], Int32Array[] | false]>;
    public readonly publicCoder: BytesCoderLen<[Uint8Array, Int32Array[]]>;
    public readonly secretCoder: BytesCoderLen<
        [Uint8Array, Uint8Array, Uint8Array, Int32Array[], Int32Array[], Int32Array[]]
    >;

    constructor(opts: PrimitivesOpts) {
        const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
        const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: _XOF128, XOF256: _XOF256 } = opts;

        if (![2, 4].includes(ETA)) throw new Error('Wrong ETA');
        if (![1 << 17, 1 << 19].includes(GAMMA1)) throw new Error('Wrong GAMMA1');
        if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2)) throw new Error('Wrong GAMMA2');

        this.K = K;
        this.L = L;
        this.GAMMA1 = GAMMA1;
        this.GAMMA2 = GAMMA2;
        this.TAU = TAU;
        this.ETA = ETA;
        this.OMEGA = OMEGA;
        this.BETA = TAU * ETA;
        this.C_TILDE_BYTES = C_TILDE_BYTES;
        this.CRH_BYTES = CRH_BYTES;
        this.TR_BYTES = TR_BYTES;
        this.XOF128 = _XOF128;
        this.XOF256 = _XOF256;

        this.#coefFromHalfByte =
            ETA === 2
                ? (n: number) => (n < 15 ? 2 - (n % 5) : false)
                : (n: number) => (n < 9 ? 4 - n : false);

        this.hintCoder = {
            bytesLen: OMEGA + K,
            encode: (h: Poly[] | false) => {
                if (h === false) throw new Error('hint.encode: hint is false');
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

        this.ETACoder = polyCoder(
            ETA === 2 ? 3 : 4,
            (i: number) => ETA - i,
            (i: number) => {
                if (!(-ETA <= i && i <= ETA))
                    throw new Error(
                        `malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`,
                    );
                return i;
            },
        );
        this.T0Coder = polyCoder(13, (i: number) => (1 << (D - 1)) - i);
        this.T1Coder = polyCoder(10);
        this.ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i: number) => smod(GAMMA1 - i));
        this.W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
        this.W1Vec = vecCoder(this.W1Coder, K);
        this.publicCoder = splitCoder('publicKey', 32, vecCoder(this.T1Coder, K));
        this.secretCoder = splitCoder(
            'secretKey',
            32,
            32,
            TR_BYTES,
            vecCoder(this.ETACoder, L),
            vecCoder(this.ETACoder, K),
            vecCoder(this.T0Coder, K),
        );
        this.sigCoder = splitCoder(
            'signature',
            C_TILDE_BYTES,
            vecCoder(this.ZCoder, L),
            this.hintCoder,
        );
    }

    /** Decompose r into (r1, r0) such that r = r1*(2*GAMMA2) + r0 mod q (FIPS 204 Algorithm 17). */
    public decompose(r: number): { r1: number; r0: number } {
        const rPlus = mod(r);
        const r0 = smod(rPlus, 2 * this.GAMMA2) | 0;
        if (rPlus - r0 === Q - 1) return { r1: 0 | 0, r0: (r0 - 1) | 0 };
        const r1 = Math.floor((rPlus - r0) / (2 * this.GAMMA2)) | 0;
        return { r1, r0 };
    }

    /** Extract high bits of r. */
    public HighBits(r: number): number {
        return this.decompose(r).r1;
    }

    /** Extract low bits of r. */
    public LowBits(r: number): number {
        return this.decompose(r).r0;
    }

    /** Compute hint bit indicating whether adding z to r alters the high bits. */
    public MakeHint(z: number, r: number): number {
        const g2 = this.GAMMA2;
        return z <= g2 || z > Q - g2 || (z === Q - g2 && r === 0) ? 0 : 1;
    }

    /** Return the high bits of r adjusted according to hint h. */
    public UseHint(h: number, r: number): number {
        const m = Math.floor((Q - 1) / (2 * this.GAMMA2));
        const { r1, r0 } = this.decompose(r);
        if (h === 1) return r0 > 0 ? mod(r1 + 1, m) | 0 : mod(r1 - 1, m) | 0;
        return r1 | 0;
    }

    /** Decompose r into (r1, r0) such that r = r1*(2^d) + r0 mod q. */
    public Power2Round(r: number): { r1: number; r0: number } {
        const rPlus = mod(r);
        const r0 = smod(rPlus, 2 ** D) | 0;
        return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
    }

    /** Apply Power2Round to each coefficient of a polynomial. */
    public polyPowerRound(p: Poly): { r0: Int32Array; r1: Int32Array } {
        const res0 = newPoly(N);
        const res1 = newPoly(N);
        for (let i = 0; i < p.length; i++) {
            const { r0, r1 } = this.Power2Round(p[i]);
            res0[i] = r0;
            res1[i] = r1;
        }
        return { r0: res0, r1: res1 };
    }

    /** Apply UseHint element-wise. **Mutates `u` in place.** */
    public polyUseHint(u: Poly, h: Poly): Poly {
        for (let i = 0; i < N; i++) u[i] = this.UseHint(h[i], u[i]);
        return u;
    }

    /** Apply MakeHint element-wise, returning the hint vector and popcount. */
    public polyMakeHint(a: Poly, b: Poly): { v: Int32Array; cnt: number } {
        const v = newPoly(N);
        let cnt = 0;
        for (let i = 0; i < N; i++) {
            const h = this.MakeHint(a[i], b[i]);
            v[i] = h;
            cnt += h;
        }
        return { v, cnt };
    }

    /** Sample a polynomial with coefficients in [-ETA, ETA] via rejection (FIPS 204 Algorithm 15). */
    public RejBoundedPoly(xof: XofGet): Int32Array {
        const r: Poly = newPoly(N);
        for (let j = 0; j < N; ) {
            const b = xof();
            for (let i = 0; j < N && i < b.length; i += 1) {
                const d1 = this.#coefFromHalfByte(b[i] & 0x0f);
                const d2 = this.#coefFromHalfByte((b[i] >> 4) & 0x0f);
                if (d1 !== false) r[j++] = d1;
                if (j < N && d2 !== false) r[j++] = d2;
            }
        }
        return r;
    }

    /** Sample a polynomial c in R_q with coefficients from {-1, 0, 1} and Hamming weight TAU (FIPS 204 Algorithm 16). */
    public SampleInBall(seed: Uint8Array): Int32Array {
        const pre = newPoly(N);
        const s = shake256.create({}).update(seed);
        const buf = new Uint8Array(shake256.blockLen);
        s.xofInto(buf);
        const masks = buf.slice(0, 8);
        for (let i = N - this.TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
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
    }
}

/**
 * Create an MLDSAPrimitives instance.
 * @deprecated Use `new MLDSAPrimitives(opts)` directly.
 */
export function createMLDSAPrimitives(opts: PrimitivesOpts): MLDSAPrimitives {
    return new MLDSAPrimitives(opts);
}

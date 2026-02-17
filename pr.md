# Threshold ML-DSA: t-of-n Threshold Signing for FIPS 204

## Summary

Adds threshold ML-DSA signing (t-of-n, where 2 <= T <= N <= 6) for all three security levels (ML-DSA-44, ML-DSA-65, ML-DSA-87). Threshold signatures are standard FIPS 204 signatures verifiable by `ml_dsa44.verify()` / `ml_dsa65.verify()` / `ml_dsa87.verify()` without knowing they were threshold-produced.

Based on the paper *"Threshold Signatures Reloaded"* (Borin, Celi, del Pino, Espitau, Niot, Prest, 2025) and ported from the Go reference implementation ([GuilhemN/threshold-ml-dsa-and-raccoon](https://github.com/GuilhemN/threshold-ml-dsa-and-raccoon), built on Cloudflare CIRCL).

## Motivation

Multi-party post-quantum custody requires threshold signing. No single party holds the full private key, but any T-of-N parties can collaboratively produce a valid signature. This is critical for Bitcoin/blockchain custody where key compromise resistance is paramount and post-quantum migration is needed.

## Architecture

### Primitives Extraction (`src/ml-dsa-primitives.ts` - new, 349 lines)

Extracts ring arithmetic, NTT, polynomial coders, sampling, and decomposition functions from the `getDilithium` closure into a reusable `createMLDSAPrimitives()` factory. Both the existing `getDilithium` and the new threshold module consume this factory. Zero behavior change to existing ML-DSA - pure refactor verified by all 109 existing tests.

### Threshold Module (`src/threshold-ml-dsa.ts` - new, 1076 lines)

- `ThresholdMLDSA` class with `#private` fields, `readonly` properties, and TSDoc
- `ThresholdMLDSA.create(securityLevel, T, N)` - factory for all valid configurations
- `ThresholdMLDSA.getParams(T, N, level)` - parameter lookup with full validation
- `keygen(seed?)` - deterministic (or random) key generation producing a standard public key + N key shares
- `sign(msg, publicKey, shares, opts?)` - local threshold signing with optional context support

### Key Internals

- **Hyperball sampling** via Box-Muller transform over SHAKE256 with BigInt-safe uint64-to-float64 conversion (`Number(u >> 11n) * 2^-53` extracts exactly 53 bits, avoiding the `Number(uint64)` precision trap where values exceed `Number.MAX_SAFE_INTEGER`)
- **Gosper's hack** for enumerating all C(N, N-T+1) subsets during DKG
- **Share recovery** via hardcoded sharing patterns computed by `params/recover.py` (max-flow optimal assignment), with permutation-based bitmask translation for arbitrary active sets
- **Combine** step matching FIPS 204 verify: `Az - 2^d * c * t1` decomposition, hint computation, standard `sigCoder.encode`

## Security Hardening

Applied all applicable findings from the [threshold ML-DSA audit report](https://github.com/GuilhemN/threshold-ml-dsa-and-raccoon):

| Finding | Severity | Fix |
|---------|----------|-----|
| **C1**: Box-Muller NaN/Infinity when `log(0)` | Critical | Clamp `f1 = 0` to `Number.MIN_VALUE` (probability: 2^-53) |
| **C8**: No input validation on `publicKey`/`msg` | Critical | `abytes()` length checks on both inputs |
| **H1**: Timing leak from rejection pattern | High | Always execute `fvecRound()` regardless of excess check result |
| **H6**: No zeroization of secret key material | High | `cleanBytes()`/`.fill(0)` on s1Hat, s2Hat, csVec, zf, mu after use; cleanup on both success and failure paths |
| **M7**: No validation on unpacked polynomial coefficients | Medium | `>= Q` check in `polyUnpackW` (for future distributed protocol) |

### Additional Hardening Beyond the Audit

- **Duplicate share ID validation**: throws on `sign()` if two shares have the same party ID, preventing incorrect bitmask construction in share recovery
- **BigInt precision**: `getBigUint64` + `>> 11n` for safe 53-bit extraction. Go uses `float64(uint64)/(1<<64)` which has double-rounding; our approach is actually more precise
- **Failure-path cleanup**: `mu` is zeroed even when all 500 signing attempts are exhausted

## Parameter Tables

- **ML-DSA-44**: All 15 (T,N) configurations ported directly from Go reference with exact `[K_iter, r, rPrime]` values
- **ML-DSA-65/87**: Derived from the same formulas, scaled for their respective (K,L) dimensions. All configurations produce valid FIPS 204 signatures (verified by tests)

## Tests (`test/threshold.test.ts` - new, 474 lines, 45 tests)

### Parameter Validation (10 tests)
- Rejects T<2, T>N, N>6, N<2, invalid security level
- Validates all 15 (T,N) combos for each of ML-DSA-44/65/87
- Tests `normalizeSecurityLevel` (128->44, 192->65, 256->87)

### Key Generation (9 tests)
- Deterministic keygen from seed, random keygen, wrong seed length rejection
- Correct share count, public key lengths for all three security levels
- Shared rho/tr across parties, unique per-party keys

### Signing - ML-DSA-44 (11 tests)
- 2-of-3 with all three party subsets (0,1), (0,2), (1,2)
- 2-of-2, 3-of-4, 3-of-3 (T=N), 4-of-4 (T=N)
- All 6 subsets of 2-of-4
- Superset of shares (providing > T shares)

### Signing - ML-DSA-65/87 (4 tests)
- 2-of-3 and 2-of-2 for each level

### Context and Edge Cases (5 tests)
- Signing with context, verification without context fails, wrong context fails
- Empty message, large (1KB) message

### Error Cases (5 tests)
- Insufficient shares, wrong publicKey length, empty publicKey, wrong seed length, duplicate share IDs

### Create with NIST Levels (3 tests)
- Levels 128/192/256 map to ML-DSA-44/65/87

## Files Changed

| File | Action | Lines | Description |
|------|--------|-------|-------------|
| `src/ml-dsa-primitives.ts` | **NEW** | 349 | Ring arithmetic, NTT, coders, sampling extracted from getDilithium |
| `src/threshold-ml-dsa.ts` | **NEW** | 1076 | ThresholdMLDSA class, interfaces, types, protocol |
| `test/threshold.test.ts` | **NEW** | 474 | 45 threshold signing tests |
| `src/ml-dsa.ts` | Modified | -300/+57 | Imports primitives from factory instead of defining locally |
| `test/index.ts` | Modified | +1 | Added threshold test import |
| `package.json` | Modified | +2 | Added `ml-dsa-primitives.js` and `threshold-ml-dsa.js` exports |

## Usage

### Local signing (convenience)

```typescript
import { ml_dsa44 } from '@btc-vision/post-quantum';
import { ThresholdMLDSA } from '@btc-vision/post-quantum/threshold-ml-dsa.js';

// 3-of-5 threshold with ML-DSA-44
const th = ThresholdMLDSA.create(44, 3, 5);
const { publicKey, shares } = th.keygen();

// Any 3 of 5 parties can sign
const sig = th.sign(message, publicKey, [shares[0], shares[2], shares[4]]);

// Standard FIPS 204 verify - no knowledge of threshold required
const valid = ml_dsa44.verify(sig, message, publicKey); // true
```

### Distributed signing (network protocol)

For multi-party signing over a network where no party shares their private key:

```typescript
import { ml_dsa44 } from '@btc-vision/post-quantum';
import { ThresholdMLDSA } from '@btc-vision/post-quantum/threshold-ml-dsa.js';

// Setup: trusted dealer generates shares, distributes securely, deletes seed
const th = ThresholdMLDSA.create(44, 2, 3);
const { publicKey, shares } = th.keygen();
// shares[0] → Party 0, shares[1] → Party 1, shares[2] → Party 2

// === Parties 0 and 1 want to sign ===
const msg = new Uint8Array([1, 2, 3]);
const activePartyIds = [0, 1];

for (let attempt = 0; ; attempt++) {
  // Round 1: each party independently generates commitment
  const r1_0 = th.round1(shares[0], { nonce: attempt });  // Party 0
  const r1_1 = th.round1(shares[1], { nonce: attempt });  // Party 1

  // → Each broadcasts commitmentHash (32 bytes)

  // Round 2: after receiving all hashes, each reveals commitment
  const allHashes = [r1_0.commitmentHash, r1_1.commitmentHash];
  const r2_0 = th.round2(shares[0], activePartyIds, msg, allHashes, r1_0.state);
  const r2_1 = th.round2(shares[1], activePartyIds, msg, allHashes, r1_1.state);

  // → Each broadcasts commitment (packed w vectors)

  // Round 3: after receiving all commitments, each computes partial response
  // (internally verifies commitments match hashes)
  const allCommitments = [r2_0.commitment, r2_1.commitment];
  const resp_0 = th.round3(shares[0], allCommitments, r1_0.state, r2_0.state);
  const resp_1 = th.round3(shares[1], allCommitments, r1_1.state, r2_1.state);

  // → Each broadcasts partial response

  // Combine: anyone with the public key can produce the signature
  const sig = th.combine(publicKey, msg, allCommitments, [resp_0, resp_1]);

  // Cleanup sensitive state
  r1_0.state.destroy(); r1_1.state.destroy();
  r2_0.state.destroy(); r2_1.state.destroy();

  if (sig) {
    const valid = ml_dsa44.verify(sig, msg, publicKey); // true
    break;
  }
  // If null, retry from Round 1 with fresh randomness
}
```

## Audit Summary

Full line-by-line audit was performed against the Go reference implementation. Verified correct:

- **Gosper's hack**: JS float division + `|` truncation produces identical results to Go integer division for N <= 6
- **polyPackW/polyUnpackW bit arithmetic**: max intermediate values are 30 bits, safely within int32
- **fvecFrom centered mod Q**: values stay within int32 range (max ~12.5M)
- **fvecRound**: hyperball bounds keep values safely within int32
- **#recoverShare permutation logic**: traced through multiple active sets, produces correct bitmask translations
- **#combine formula**: `Az - 2^d*c*t1` matches Go exactly, including `.slice()` to protect t1 from in-place `polyShiftl`
- **#computeResponses challenge**: `H(mu || W1Vec(HighBits(wfinal)))` matches `#combine`'s challenge derivation
- **sampleHyperball**: sq accumulation order and nu scaling match Go reference exactly (sq accumulated from unscaled samples before nu scaling, including extra Box-Muller pair beyond dim)
- **All polynomial arithmetic**: stays within 46 bits (Q is 23 bits, Q*Q is 46 bits), no 53-bit overflow

## Known Limitations

- **No side-channel protection**: inherited from noble-post-quantum. JS cannot guarantee constant-time operations
- **Float64 platform dependence**: `Math.sqrt`/`Math.cos`/`Math.sin`/`Math.log` may differ by ULP across platforms. Each platform produces independently valid signatures, but cross-platform deterministic signing is not guaranteed
- **Trusted dealer keygen**: `keygen()` generates all shares in one place (trusted dealer model from the paper). For environments where no party can be trusted, use external MPC to generate the shared seed
- **Identifiable aborts**: not yet exposed. If a signing attempt fails, the protocol retries but does not identify which party caused the failure
- **Unaudited**: this is a port of an academic reference implementation. Not for production custody without formal audit

/**
 * Example: Trusted Dealer Threshold Key Generation + Signing
 *
 * Demonstrates the trusted dealer model where a single party generates
 * all threshold key shares, then distributes them. After distribution,
 * any T-of-N parties can produce a standard FIPS 204 ML-DSA signature.
 *
 * Run with: node --experimental-strip-types --no-warnings examples/threshold-keygen.ts
 */
import { ml_dsa44 } from '../src/ml-dsa.ts';
import { ThresholdMLDSA } from '../src/threshold-ml-dsa.ts';

// Parameters: 2-of-3 threshold with ML-DSA-44 security level
const T = 2; // minimum signers needed
const N = 3; // total parties
const securityLevel = 44; // ML-DSA-44 (also supports 65, 87)

const th = ThresholdMLDSA.create(securityLevel, T, N);

// --- Trusted Dealer Key Generation ---
// A single trusted party generates all shares from a random seed.
// After distributing shares over secure channels, the dealer MUST
// destroy the seed and all share data.
const { publicKey, shares } = th.keygen();

console.log(`Public key (${publicKey.length} bytes)`);
console.log(`Generated ${shares.length} shares for ${N} parties`);

// Each party gets their own ThresholdKeyShare.
// Party 0 gets shares[0], Party 1 gets shares[1], etc.
for (const share of shares) {
  console.log(`  Party ${share.id}: ${share.shares.size} bitmask shares`);
}

// --- Threshold Signing (local convenience method) ---
// Any T parties can sign. Here parties 0 and 1 sign together.
const message = new TextEncoder().encode('Hello, post-quantum world!');
const activeShares = [shares[0], shares[1]]; // any 2 of 3

const signature = th.sign(message, publicKey, activeShares);
console.log(`\nSignature (${signature.length} bytes)`);

// --- Verification with standard ML-DSA ---
// The signature is a standard FIPS 204 signature — verifiers don't
// need to know it was threshold-produced.
const valid = ml_dsa44.verify(signature, message, publicKey);
console.log(`Verified with ml_dsa44.verify(): ${valid}`);

// --- Any T subset works ---
// Parties 1 and 2 can also sign the same message.
const sig2 = th.sign(message, publicKey, [shares[1], shares[2]]);
console.log(`Different subset signature valid: ${ml_dsa44.verify(sig2, message, publicKey)}`);

// Parties 0 and 2 work too.
const sig3 = th.sign(message, publicKey, [shares[0], shares[2]]);
console.log(`Another subset signature valid: ${ml_dsa44.verify(sig3, message, publicKey)}`);

/**
 * Example: Threshold Signing with Context
 *
 * ML-DSA supports an optional context parameter that binds the signature
 * to a specific application context (up to 255 bytes). This example shows
 * how to use context with both the local sign() and distributed protocol.
 *
 * Run with: node --experimental-strip-types --no-warnings examples/threshold-signing-with-context.ts
 */
import { ml_dsa87 } from '../src/ml-dsa.ts';
import { ThresholdMLDSA } from '../src/threshold-ml-dsa.ts';

// 3-of-5 threshold with ML-DSA-87 (highest security level)
const th = ThresholdMLDSA.create(87, 3, 5);
const { publicKey, shares } = th.keygen();

const message = new TextEncoder().encode('Transfer 100 BTC to Alice');
const context = new TextEncoder().encode('bitcoin-multisig-v1');

// --- Local signing with context ---
const signature = th.sign(message, publicKey, [shares[0], shares[1], shares[2]], {
  context,
});
console.log(`Signature with context (${signature.length} bytes)`);

// Verification MUST include the same context
const valid = ml_dsa87.verify(signature, message, publicKey, { context });
console.log(`Verified with matching context: ${valid}`);

// Wrong context fails verification
const wrongCtx = new TextEncoder().encode('wrong-context');
const invalid = ml_dsa87.verify(signature, message, publicKey, { context: wrongCtx });
console.log(`Verified with wrong context: ${invalid}`);

// No context also fails
const noCtx = ml_dsa87.verify(signature, message, publicKey);
console.log(`Verified with no context: ${noCtx}`);

// --- Distributed signing with context ---
const activeShares = [shares[2], shares[3], shares[4]];
const activeIds = activeShares.map((s) => s.id);

const r1 = activeShares.map((s) => th.round1(s));
const hashes = r1.map((r) => r.commitmentHash);

// Context is passed in round2 (where the message is bound)
const r2 = activeShares.map((s, i) =>
  th.round2(s, activeIds, message, hashes, r1[i].state, { context })
);
const commitments = r2.map((r) => r.commitment);

const responses = activeShares.map((s, i) =>
  th.round3(s, commitments, r1[i].state, r2[i].state)
);

// Context must also be passed to combine
const sig2 = th.combine(publicKey, message, commitments, responses, { context });
if (sig2) {
  console.log(`\nDistributed signature with context: ${ml_dsa87.verify(sig2, message, publicKey, { context })}`);
}

// Clean up
for (const r of r1) r.state.destroy();
for (const r of r2) r.state.destroy();

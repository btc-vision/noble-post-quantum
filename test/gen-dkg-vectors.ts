/**
 * Generate deterministic DKG test vectors.
 * Run with: node --experimental-strip-types --no-warnings test/gen-dkg-vectors.ts
 */
import { writeFileSync } from 'node:fs';
import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
    ThresholdMLDSA,
    type DKGPhase1Broadcast,
    type DKGPhase1State,
    type DKGPhase2Broadcast,
    type DKGPhase2Private,
    type DKGPhase3Private,
    type DKGPhase2FinalizeResult,
} from '../src/threshold-ml-dsa.ts';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';

function deriveEntropy(seed: string, label: string, index: number, len: number): Uint8Array {
    return shake256(new TextEncoder().encode(`${seed}|${label}|${index}`), { dkLen: len });
}

interface VectorParty {
    id: number;
    rho: string;
    bitmaskEntropy: Record<string, string>;
}

interface DKGVector {
    securityLevel: number;
    T: number;
    N: number;
    sessionId: string;
    parties: VectorParty[];
    expectedRho: string;
    expectedPublicKey: string;
    bitmasks: number[];
    generatorAssignment: Record<string, number>;
}

function generateVector(securityLevel: number, T: number, N_: number, seedStr: string): DKGVector {
    const th = ThresholdMLDSA.create(securityLevel, T, N_);
    const sid = deriveEntropy(seedStr, 'sid', 0, 32);
    const { bitmasks } = th.dkgSetup(sid);

    // Generate deterministic entropy for each party
    const partyData: VectorParty[] = [];
    const phase1Opts: { rho: Uint8Array; bitmaskEntropy: Map<number, Uint8Array> }[] = [];

    for (let i = 0; i < N_; i++) {
        const rho = deriveEntropy(seedStr, 'rho', i, 32);
        const bitmaskEntropy = new Map<number, Uint8Array>();
        const bitmaskEntropyHex: Record<string, string> = {};

        for (const b of bitmasks) {
            if (b & (1 << i)) {
                const ent = deriveEntropy(seedStr, `r_${i}_${b}`, 0, 32);
                bitmaskEntropy.set(b, ent);
                bitmaskEntropyHex[String(b)] = bytesToHex(ent);
            }
        }

        partyData.push({ id: i, rho: bytesToHex(rho), bitmaskEntropy: bitmaskEntropyHex });
        phase1Opts.push({ rho, bitmaskEntropy });
    }

    // Run DKG
    const phase1: { broadcast: DKGPhase1Broadcast; state: DKGPhase1State }[] = [];
    for (let i = 0; i < N_; i++) {
        phase1.push(th.dkgPhase1(i, sid, phase1Opts[i]));
    }
    const allPhase1 = phase1.map((r) => r.broadcast);

    const phase2: {
        broadcast: DKGPhase2Broadcast;
        privateToHolders: Map<number, DKGPhase2Private>;
    }[] = [];
    for (let i = 0; i < N_; i++) {
        phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
    }
    const allPhase2 = phase2.map((r) => r.broadcast);

    const receivedReveals: DKGPhase2Private[][] = Array.from({ length: N_ }, () => []);
    for (let i = 0; i < N_; i++) {
        for (const [targetId, msg] of phase2[i].privateToHolders) {
            receivedReveals[targetId].push(msg);
        }
    }

    const finalize: DKGPhase2FinalizeResult[] = [];
    for (let i = 0; i < N_; i++) {
        finalize.push(
            th.dkgPhase2Finalize(i, sid, phase1[i].state, allPhase1, allPhase2, receivedReveals[i]),
        );
    }

    const receivedMasks: DKGPhase3Private[][] = Array.from({ length: N_ }, () => []);
    for (let i = 0; i < N_; i++) {
        for (const [targetId, msg] of finalize[i].privateToAll) {
            receivedMasks[targetId].push(msg);
        }
    }

    const setup = th.dkgSetup(sid);
    const phase4 = [];
    for (let i = 0; i < N_; i++) {
        phase4.push(
            th.dkgPhase4(
                i,
                setup.bitmasks,
                finalize[i].generatorAssignment,
                receivedMasks[i],
                finalize[i].ownMaskPieces,
            ),
        );
    }

    const results = [];
    for (let i = 0; i < N_; i++) {
        results.push(th.dkgFinalize(i, finalize[i].rho, phase4, finalize[i].shares));
    }

    // Verify test signing
    const msg = new Uint8Array([0x54, 0x45, 0x53, 0x54]); // "TEST"
    const activeShares = results.slice(0, T).map((r) => r.share);
    const sig = th.sign(msg, results[0].publicKey, activeShares);

    const verify = securityLevel === 44 ? ml_dsa44 : securityLevel === 65 ? ml_dsa65 : ml_dsa87;

    if (!verify.verify(sig, msg, results[0].publicKey)) {
        throw new Error(`Test signing failed for (${T},${N_}) level ${securityLevel}`);
    }

    const genAssign: Record<string, number> = {};
    for (const [b, gen] of finalize[0].generatorAssignment) {
        genAssign[String(b)] = gen;
    }

    return {
        securityLevel,
        T,
        N: N_,
        sessionId: bytesToHex(sid),
        parties: partyData,
        expectedRho: bytesToHex(finalize[0].rho),
        expectedPublicKey: bytesToHex(results[0].publicKey),
        bitmasks: [...bitmasks],
        generatorAssignment: genAssign,
    };
}

// Generate vectors for various (T, N, securityLevel) combinations
const vectors: DKGVector[] = [];

// ML-DSA-44
vectors.push(generateVector(44, 2, 2, 'ml-dsa-44-2-2'));
vectors.push(generateVector(44, 2, 3, 'ml-dsa-44-2-3'));
vectors.push(generateVector(44, 3, 4, 'ml-dsa-44-3-4'));
vectors.push(generateVector(44, 2, 4, 'ml-dsa-44-2-4'));
vectors.push(generateVector(44, 3, 5, 'ml-dsa-44-3-5'));
vectors.push(generateVector(44, 4, 4, 'ml-dsa-44-4-4'));

// ML-DSA-65
vectors.push(generateVector(65, 2, 3, 'ml-dsa-65-2-3'));
vectors.push(generateVector(65, 2, 2, 'ml-dsa-65-2-2'));

// ML-DSA-87
vectors.push(generateVector(87, 2, 3, 'ml-dsa-87-2-3'));
vectors.push(generateVector(87, 2, 2, 'ml-dsa-87-2-2'));

const output = {
    algorithm: 'threshold-ml-dsa-dkg',
    version: '1.0',
    description: 'Deterministic DKG test vectors for threshold ML-DSA distributed key generation',
    vectors,
};

const json = JSON.stringify(output, null, 2);
writeFileSync('/root/acvp-vectors/gen-val/threshold-ml-dsa-dkg.json', json);
console.log(`Generated ${vectors.length} DKG test vectors`);
console.log(`Written to /root/acvp-vectors/gen-val/threshold-ml-dsa-dkg.json`);

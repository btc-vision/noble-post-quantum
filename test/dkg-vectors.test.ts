import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { hexToBytes } from '@noble/hashes/utils.js';
import {
    ThresholdMLDSA,
    type DKGPhase1Broadcast,
    type DKGPhase1State,
    type DKGPhase2Broadcast,
    type DKGPhase2Private,
    type DKGPhase3Private,
    type DKGPhase2FinalizeResult,
} from '../src/threshold-ml-dsa.ts';
import { jsonGZ } from './util.ts';

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

function runDKGFromVector(vector: DKGVector) {
    const th = ThresholdMLDSA.create(vector.securityLevel, vector.T, vector.N);
    const sid = hexToBytes(vector.sessionId);

    // Phase 1: use deterministic entropy from vector
    const phase1: { broadcast: DKGPhase1Broadcast; state: DKGPhase1State }[] = [];
    for (const party of vector.parties) {
        const bitmaskEntropy = new Map<number, Uint8Array>();
        for (const [bStr, hex] of Object.entries(party.bitmaskEntropy)) {
            bitmaskEntropy.set(Number(bStr), hexToBytes(hex));
        }
        phase1.push(
            th.dkgPhase1(party.id, sid, {
                rho: hexToBytes(party.rho),
                bitmaskEntropy,
            }),
        );
    }
    const allPhase1 = phase1.map((r) => r.broadcast);

    // Phase 2
    const phase2: {
        broadcast: DKGPhase2Broadcast;
        privateToHolders: Map<number, DKGPhase2Private>;
    }[] = [];
    for (let i = 0; i < vector.N; i++) {
        phase2.push(th.dkgPhase2(i, sid, phase1[i].state, allPhase1));
    }
    const allPhase2 = phase2.map((r) => r.broadcast);

    // Distribute reveals
    const receivedReveals: DKGPhase2Private[][] = Array.from({ length: vector.N }, () => []);
    for (let i = 0; i < vector.N; i++) {
        for (const [targetId, msg] of phase2[i].privateToHolders) {
            receivedReveals[targetId].push(msg);
        }
    }

    // Phase 2 Finalize
    const finalize: DKGPhase2FinalizeResult[] = [];
    for (let i = 0; i < vector.N; i++) {
        finalize.push(
            th.dkgPhase2Finalize(i, sid, phase1[i].state, allPhase1, allPhase2, receivedReveals[i]),
        );
    }

    // Distribute masks
    const receivedMasks: DKGPhase3Private[][] = Array.from({ length: vector.N }, () => []);
    for (let i = 0; i < vector.N; i++) {
        for (const [targetId, msg] of finalize[i].privateToAll) {
            receivedMasks[targetId].push(msg);
        }
    }

    // Phase 4
    const setup = th.dkgSetup(sid);
    const phase4 = [];
    for (let i = 0; i < vector.N; i++) {
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

    // Finalize
    const results = [];
    for (let i = 0; i < vector.N; i++) {
        results.push(th.dkgFinalize(i, finalize[i].rho, phase4, finalize[i].shares));
    }

    return { rho: finalize[0].rho, publicKey: results[0].publicKey, finalize, results };
}

// Load vectors
let vectors: { vectors: DKGVector[] };
try {
    vectors = jsonGZ('vectors/acvp-vectors/gen-val/threshold-ml-dsa-dkg.json');
} catch {
    vectors = { vectors: [] };
}

if (vectors.vectors.length > 0) {
    describe('DKG Test Vectors', () => {
        for (const vector of vectors.vectors) {
            const label = `ML-DSA-${vector.securityLevel} (${vector.T},${vector.N})`;

            should(`${label}: rho matches expected`, () => {
                const { rho } = runDKGFromVector(vector);
                eql(rho, hexToBytes(vector.expectedRho));
            });

            should(`${label}: public key matches expected`, () => {
                const { publicKey } = runDKGFromVector(vector);
                eql(publicKey, hexToBytes(vector.expectedPublicKey));
            });

            should(`${label}: generator assignment matches expected`, () => {
                const { finalize } = runDKGFromVector(vector);
                for (const [bStr, expectedGen] of Object.entries(vector.generatorAssignment)) {
                    eql(finalize[0].generatorAssignment.get(Number(bStr)), expectedGen);
                }
            });
        }
    });
}

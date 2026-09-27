// Differential test against algod's `vrf_verify VrfAlgorand` (Algorand's libsodium fork).
// Requires LocalNet: `algokit localnet start`, then `npm run test:e2e`.
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import { randomBytes, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";
import { bytesToHex, hexToBytes, init, keyPairFromSeed, prove, verify } from "../src/index";

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const P = (1n << 255n) - 19n;
const RANDOM_CASES = 100;

// The creation call verifies (message, proof, publicKey) and logs itob(valid) || output.
const approval = `#pragma version 10
txna ApplicationArgs 0
txna ApplicationArgs 1
txna ApplicationArgs 2
vrf_verify VrfAlgorand
itob
swap
concat
log
int 1`;

const littleEndianToBigInt = (bytes: Uint8Array) =>
  [...bytes].reduceRight((n, byte) => (n << 8n) + BigInt(byte), 0n);
const bigIntToLittleEndian = (n: bigint) =>
  Uint8Array.from({ length: 32 }, (_, index) => Number((n >> BigInt(8 * index)) & 0xffn));

type Case = [message: Uint8Array, proof: Uint8Array, publicKey: Uint8Array];
type AvmResult = { valid: boolean; output: string } | { error: string };

let avmVerify: (
  message: Uint8Array,
  proof: Uint8Array,
  publicKey: Uint8Array,
) => Promise<AvmResult>;

/** Returns every case where the package's verify() and the AVM disagree. */
async function disagreements(cases: Case[]) {
  const mismatches = [];
  for (const [message, proof, publicKey] of cases) {
    const avm = await avmVerify(message, proof, publicKey);
    const local = verify(publicKey, message, proof);
    const localOutput = local && bytesToHex(local);
    const avmOutput = "valid" in avm && avm.valid ? avm.output : null;
    if (localOutput !== avmOutput) {
      mismatches.push({
        avm,
        local: localOutput,
        message: bytesToHex(message),
        proof: bytesToHex(proof),
        publicKey: bytesToHex(publicKey),
      });
    }
  }
  return mismatches;
}

function randomProof() {
  const { publicKey, secretKey } = keyPairFromSeed(randomBytes(32));
  const message = randomBytes(randomInt(0, 1800));
  return { publicKey, message, ...prove(secretKey, message) };
}

function flipBit(bytes: Uint8Array) {
  const flipped = new Uint8Array(bytes);
  flipped[randomInt(bytes.length)] ^= 1 << randomInt(8);
  return flipped;
}

beforeAll(async () => {
  await init();

  const algorand = AlgorandClient.defaultLocalNet();
  const algod = algorand.client.algod;
  await algod
    .status()
    .do()
    .catch((error: unknown) => {
      throw new Error(
        `LocalNet algod is not reachable; run \`algokit localnet start\` (${String(error)})`,
      );
    });

  const compile = async (source: string) =>
    new Uint8Array(Buffer.from((await algod.compile(Buffer.from(source)).do()).result, "base64"));
  const approvalProgram = await compile(approval);
  const clearProgram = await compile("#pragma version 10\nint 1");
  const sender = (await algorand.account.localNetDispenser()).addr;
  const suggestedParams = await algod.getTransactionParams().do();

  // Simulated app creation: nothing is deployed, and extra budget covers vrf_verify's 5700 cost.
  avmVerify = async (message, proof, publicKey) => {
    const txn = algosdk.makeApplicationCreateTxnFromObject({
      sender,
      suggestedParams,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      approvalProgram,
      clearProgram,
      numGlobalInts: 0,
      numGlobalByteSlices: 0,
      numLocalInts: 0,
      numLocalByteSlices: 0,
      appArgs: [message, proof, publicKey],
      note: randomBytes(8),
    });
    const request = new algosdk.modelsv2.SimulateRequest({
      txnGroups: [
        new algosdk.modelsv2.SimulateRequestTransactionGroup({
          txns: [new algosdk.SignedTransaction({ txn })],
        }),
      ],
      allowEmptySignatures: true,
      extraOpcodeBudget: 20000,
    });
    const group = (await algod.simulateTransactions(request).do()).txnGroups[0];
    if (group.failureMessage) return { error: group.failureMessage };
    const log = group.txnResults[0].txnResult.logs![0];
    return {
      valid: Buffer.from(log.subarray(0, 8)).readBigUInt64BE() === 1n,
      output: bytesToHex(log.subarray(8)),
    };
  };
});

describe("AVM vrf_verify VrfAlgorand parity", { timeout: 120_000 }, () => {
  test("accepts package proofs with the same output", async () => {
    const mismatches = [];
    for (let index = 0; index < RANDOM_CASES; index++) {
      const { publicKey, message, proof, output } = randomProof();
      const avm = await avmVerify(message, proof, publicKey);
      if (!("valid" in avm) || !avm.valid || avm.output !== bytesToHex(output)) {
        mismatches.push({
          avm,
          output: bytesToHex(output),
          message: bytesToHex(message),
          publicKey: bytesToHex(publicKey),
        });
      }
    }
    expect(mismatches).toEqual([]);
  });

  test("accepts the fixture vectors, including the IETF draft-03 examples", async () => {
    const vectors = JSON.parse(
      readFileSync(resolve(__dirname, "../fixtures/draft03-vectors.json"), "utf8"),
    ) as Array<{
      suite: string;
      message: string;
      proof: string;
      publicKey: string;
    }>;
    const cases = vectors
      .filter(({ suite }) => suite === "draft03")
      .map(({ message, proof, publicKey }): Case => [
        hexToBytes(message),
        hexToBytes(proof),
        hexToBytes(publicKey),
      ]);

    for (const [message, proof, publicKey] of cases) {
      expect(await avmVerify(message, proof, publicKey)).toMatchObject({ valid: true });
    }
    expect(await disagreements(cases)).toEqual([]);
  });

  test("agrees on tampered proofs, public keys and messages", async () => {
    const cases: Case[] = [];
    for (let index = 0; index < RANDOM_CASES; index++) {
      const { publicKey, message, proof } = randomProof();
      cases.push([message, flipBit(proof), publicKey], [message, proof, flipBit(publicKey)]);
      if (message.length) cases.push([flipBit(message), proof, publicKey]);
    }
    expect(await disagreements(cases)).toEqual([]);
  });

  test("agrees on non-canonical scalars (s + L, c high bit)", async () => {
    const cases: Case[] = [];
    for (let index = 0; index < 20; index++) {
      const { publicKey, message, proof } = randomProof();
      const sPlusL = new Uint8Array(proof);
      sPlusL.set(bigIntToLittleEndian(littleEndianToBigInt(proof.subarray(48)) + L), 48);
      const cHighBit = new Uint8Array(proof);
      cHighBit[47] ^= 0x80;
      cases.push([message, sPlusL, publicKey], [message, cHighBit, publicKey]);
    }
    expect(await disagreements(cases)).toEqual([]);
  });

  test("agrees on small-order and non-canonical points", async () => {
    const { publicKey, message, proof } = randomProof();
    const smallOrderPublicKeys = [
      "0100000000000000000000000000000000000000000000000000000000000000",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ];
    const cases: Case[] = smallOrderPublicKeys.map((key) => [message, proof, hexToBytes(key)]);
    // y + p for y < 19 is a non-canonical encoding of a field element y.
    for (let y = 0n; y < 19n; y++) {
      const nonCanonical = bigIntToLittleEndian(y + P);
      const gamma = new Uint8Array(proof);
      gamma.set(nonCanonical, 0);
      cases.push([message, proof, nonCanonical], [message, gamma, publicKey]);
    }
    expect(await disagreements(cases)).toEqual([]);
  });

  test("agrees on random bytes", async () => {
    const cases: Case[] = [];
    for (let index = 0; index < 50; index++)
      cases.push([randomBytes(randomInt(0, 64)), randomBytes(80), randomBytes(32)]);
    expect(await disagreements(cases)).toEqual([]);
  });
});

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  generateKeyPair,
  hexToBytes,
  init,
  keyPairFromSeed,
  proofToHash,
  prove,
  verify,
  VRF_OUTPUT_SIZE,
  VRF_PRIVATE_KEY_SIZE,
  VRF_PROOF_SIZE,
  VRF_PUBLIC_KEY_SIZE,
} from "../src/index";

const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const message = new TextEncoder().encode("Algorand draft-03 interoperability");
// Recorded from Algorand's libsodium draft-03 WASM; the ietf-* proofs are the draft's published examples.
const vectors = JSON.parse(
  readFileSync(resolve(__dirname, "../fixtures/draft03-vectors.json"), "utf8"),
) as Array<{
  name: string;
  suite: string;
  seed: string;
  publicKey: string;
  secretKey: string;
  message: string;
  proof: string;
  output: string;
}>;

beforeAll(init);

describe("draft-03 VRF", () => {
  test.each(vectors.filter(({ suite }) => suite === "draft03"))(
    "matches libsodium vector $name byte for byte",
    (vector) => {
      const vectorMessage = hexToBytes(vector.message);
      const { publicKey, secretKey } = keyPairFromSeed(hexToBytes(vector.seed));
      const { proof, output } = prove(secretKey, vectorMessage);

      expect(bytesToHex(publicKey)).toBe(vector.publicKey);
      expect(bytesToHex(secretKey)).toBe(vector.secretKey);
      expect(bytesToHex(proof)).toBe(vector.proof);
      expect(bytesToHex(output)).toBe(vector.output);
      expect(bytesToHex(verify(publicKey, vectorMessage, proof)!)).toBe(vector.output);
    },
  );

  test("rejects the incompatible RFC 9381 proof", () => {
    const vector = vectors.find(({ suite }) => suite === "rfc9381")!;

    expect(
      verify(hexToBytes(vector.publicKey), hexToBytes(vector.message), hexToBytes(vector.proof)),
    ).toBeNull();
  });

  test("derives a deterministic Algorand key pair from a seed", () => {
    const first = keyPairFromSeed(seed);
    const second = keyPairFromSeed(seed);

    expect(first).toEqual(second);
    expect(first.publicKey).toHaveLength(VRF_PUBLIC_KEY_SIZE);
    expect(first.secretKey).toHaveLength(VRF_PRIVATE_KEY_SIZE);
    expect(first.secretKey.slice(0, 32)).toEqual(seed);
    expect(first.secretKey.slice(32)).toEqual(first.publicKey);
  });

  test("proves, hashes, and verifies with byte-for-byte output parity", () => {
    const { publicKey, secretKey } = keyPairFromSeed(seed);
    const { proof, output } = prove(secretKey, message);

    expect(proof).toHaveLength(VRF_PROOF_SIZE);
    expect(output).toHaveLength(VRF_OUTPUT_SIZE);
    expect(proofToHash(proof)).toEqual(output);
    expect(verify(publicKey, message, proof)).toEqual(output);
  });

  test("rejects bit changes to the message, proof, and public key", () => {
    const { publicKey, secretKey } = keyPairFromSeed(seed);
    const { proof } = prove(secretKey, message);

    const changedMessage = new Uint8Array(message);
    changedMessage[0] ^= 1;
    const changedProof = new Uint8Array(proof);
    changedProof[40] ^= 1;
    const changedPublicKey = new Uint8Array(publicKey);
    changedPublicKey[0] ^= 1;

    expect(verify(publicKey, changedMessage, proof)).toBeNull();
    expect(verify(publicKey, message, changedProof)).toBeNull();
    expect(verify(changedPublicKey, message, proof)).toBeNull();
  });

  test("validates fixed-width inputs before crossing the WASM boundary", () => {
    const { publicKey, secretKey } = keyPairFromSeed(seed);
    const { proof } = prove(secretKey, message);

    expect(() => keyPairFromSeed(seed.slice(1))).toThrow(/32 bytes/u);
    expect(() => prove(secretKey.slice(1), message)).toThrow(/64 bytes/u);
    expect(() => verify(publicKey, message, proof.slice(1))).toThrow(/80 bytes/u);
  });

  test("reports malformed proofs without breaking later calls", () => {
    expect(() => proofToHash(new Uint8Array(VRF_PROOF_SIZE).fill(0xff))).toThrow(
      /proof-to-hash failed/u,
    );
    expect(prove(keyPairFromSeed(seed).secretKey, message).proof).toHaveLength(VRF_PROOF_SIZE);
  });

  test("generates independent key pairs", () => {
    const first = generateKeyPair();
    const second = generateKeyPair();

    expect(first.publicKey).toHaveLength(VRF_PUBLIC_KEY_SIZE);
    expect(first.secretKey).toHaveLength(VRF_PRIVATE_KEY_SIZE);
    expect(first.publicKey).not.toEqual(second.publicKey);
  });
});

describe("encoding", () => {
  test("round-trips explicit hexadecimal and base64 encodings", () => {
    expect(hexToBytes(bytesToHex(message))).toEqual(message);
    expect(base64ToBytes(bytesToBase64(message))).toEqual(message);
    expect(() => hexToBytes("0xz1")).toThrow(/hexadecimal/u);
    expect(() => base64ToBytes("not base64")).toThrow(/base64/u);
  });
});

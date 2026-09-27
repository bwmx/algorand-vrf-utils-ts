import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  VRF_PRIVATE_KEY_SIZE,
  VRF_PROOF_SIZE,
  VRF_PUBLIC_KEY_SIZE,
  VRF_SEED_SIZE,
} from "./constants";

/** Exports of go/main.go (github.com/tmc/vrf/draft03 compiled to WASM). */
interface GoResult {
  value?: Uint8Array;
  error?: string;
}

// Go's wasm_exec.js defines this class on globalThis.
interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

interface GoVrf {
  prove(secretKey: Uint8Array, message: Uint8Array): GoResult;
  verify(publicKey: Uint8Array, message: Uint8Array, proof: Uint8Array): GoResult;
  proofToHash(proof: Uint8Array): GoResult;
}

export interface VrfKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface VrfProofResult {
  proof: Uint8Array;
  output: Uint8Array;
}

let vrf: GoVrf | undefined;
let initialization: Promise<void> | undefined;

function assertLength(value: Uint8Array, size: number, name: string): void {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (value.length !== size) {
    throw new RangeError(`${name} must contain exactly ${size} bytes; received ${value.length}`);
  }
}

function assertMessage(message: Uint8Array): void {
  if (!(message instanceof Uint8Array)) {
    throw new TypeError("message must be a Uint8Array");
  }
}

function requireInitialized(): GoVrf {
  if (!vrf) {
    throw new Error("algorand-vrf-utils-ts is not initialized; call and await init() first");
  }
  return vrf;
}

function unwrap(result: GoResult, operation: string): Uint8Array {
  if (result.error !== undefined)
    throw new Error(`algorand-vrf-utils-ts ${operation} failed: ${result.error}`);
  return result.value!;
}

export function isInitialized(): boolean {
  return vrf !== undefined;
}

export function init(): Promise<void> {
  initialization ??= (async () => {
    require("../wasm/wasm_exec.js");
    const go = new (globalThis as unknown as { Go: new () => GoRuntime }).Go();
    const { instance } = await WebAssembly.instantiate(
      readFileSync(join(__dirname, "../wasm/vrf.wasm")),
      go.importObject,
    );
    // main() registers globalThis.algoVrf synchronously, then blocks forever to keep the exports alive.
    void go.run(instance);
    const globals = globalThis as { algoVrf?: GoVrf };
    vrf = globals.algoVrf;
    delete globals.algoVrf;
  })();
  return initialization;
}

export function generateKeyPair(): VrfKeyPair {
  return keyPairFromSeed(randomBytes(VRF_SEED_SIZE));
}

/** Derive the standard 64-byte Ed25519 `seed || publicKey` secret key. */
export function keyPairFromSeed(seed: Uint8Array): VrfKeyPair {
  assertLength(seed, VRF_SEED_SIZE, "seed");

  // RFC 8410 PKCS#8 prefix for a raw Ed25519 seed.
  const privateDer = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const privateKey = createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = new Uint8Array(publicDer.subarray(publicDer.length - VRF_PUBLIC_KEY_SIZE));
  const secretKey = new Uint8Array(VRF_PRIVATE_KEY_SIZE);
  secretKey.set(seed);
  secretKey.set(publicKey, VRF_SEED_SIZE);

  return { publicKey, secretKey };
}

export function proofToHash(proof: Uint8Array): Uint8Array {
  const go = requireInitialized();
  assertLength(proof, VRF_PROOF_SIZE, "proof");

  return unwrap(go.proofToHash(proof), "proof-to-hash");
}

export function prove(secretKey: Uint8Array, message: Uint8Array): VrfProofResult {
  const go = requireInitialized();
  assertLength(secretKey, VRF_PRIVATE_KEY_SIZE, "secretKey");
  assertMessage(message);

  const proof = unwrap(go.prove(secretKey, message), "prove");
  return { proof, output: proofToHash(proof) };
}

/** Returns the VRF output, or `null` when the proof does not verify. */
export function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  proof: Uint8Array,
): Uint8Array | null {
  const go = requireInitialized();
  assertLength(publicKey, VRF_PUBLIC_KEY_SIZE, "publicKey");
  assertMessage(message);
  assertLength(proof, VRF_PROOF_SIZE, "proof");

  const result = go.verify(publicKey, message, proof);
  return result.error === undefined ? result.value! : null;
}

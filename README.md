# `@bwmx/algorand-vrf-utils-ts`

Node wrapper for the Algorand-compatible
ECVRF-ED25519-SHA512-Elligator2 construction from IETF draft-03, implemented by
[`github.com/tmc/vrf/draft03`](https://github.com/tmc/vrf) compiled to WASM. This is
deliberately not RFC 9381: proofs made by the final RFC are incompatible with
the AVM `vrf_verify VrfAlgorand` opcode.

The public wire sizes are fixed:

- seed: 32 bytes
- public key: 32 bytes
- private key: 64 bytes (`seed || publicKey`)
- proof: 80 bytes
- output: 64 bytes

## Usage

```bash
pnpm add @bwmx/algorand-vrf-utils-ts
```

```ts
import { init, keyPairFromSeed, prove, verify } from "@bwmx/algorand-vrf-utils-ts";

await init();

const seed = new Uint8Array(32);
const message = new TextEncoder().encode("message");
const { publicKey, secretKey } = keyPairFromSeed(seed);
const { proof, output } = prove(secretKey, message);

if (!verify(publicKey, message, proof)) {
  throw new Error("proof did not verify");
}
```

All cryptographic inputs are `Uint8Array`; encoding belongs at system
boundaries. `hexToBytes`, `bytesToHex`, `base64ToBytes`, and `bytesToBase64`
are exported for those boundaries.

## Building the WASM

`go/main.go` exposes `prove`, `verify` and `proofToHash` from `tmc/vrf/draft03`.
The build output (`wasm/vrf.wasm` and Go's matching `wasm/wasm_exec.js`) is
committed, so installing the package needs no Go toolchain. After changing
`go/`, rebuild it (Go 1.24+; the output is reproducible for a given Go version).
`go/build.sh` also regenerates `THIRD_PARTY_NOTICES.md` from the licenses of
the Go runtime and every module linked into `vrf.wasm`:

```bash
pnpm run build:wasm
```

## Interoperability

`fixtures/draft03-vectors.json` was recorded from Algorand's libsodium draft-03
implementation (the C/Emscripten build this package used before). It includes
the draft's published examples (`ietf-draft03-example-*`), a multi-block
message, and an RFC 9381 proof that must be rejected. Unit tests require the Go
WASM to match every vector byte-for-byte. `go/main.go` also rejects
non-canonical Gamma encodings, as libsodium and the AVM do.

`pnpm run test:e2e` is the compatibility gate against algod itself (Algorand's
libsodium fork). It checks the package against LocalNet's
`vrf_verify VrfAlgorand` opcode through simulated app calls: random proofs must
verify with identical output, and tampered proofs, keys and messages,
non-canonical scalars and points, small-order keys and random bytes must get the
same accept/reject result from both. It is not part of `pnpm test`.

```bash
pnpm test              # unit tests, no network
algokit localnet start
pnpm run test:e2e
```

The package exposes named exports only. Invalid inputs throw before entering
the WASM boundary, and cryptographically invalid proofs make `verify()` return
`null`.

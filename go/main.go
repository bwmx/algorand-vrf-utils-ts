//go:build js && wasm

// Command vrf exposes github.com/tmc/vrf/draft03 to JavaScript as globalThis.algoVrf.
// Build with `npm run build:wasm`; src/vrf.ts loads the output and does input validation.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"syscall/js"

	"filippo.io/edwards25519"
	"github.com/tmc/vrf/draft03"
)

func bytesFromJS(v js.Value) []byte {
	b := make([]byte, v.Length())
	js.CopyBytesToGo(b, v)
	return b
}

func bytesToJS(b []byte) js.Value {
	v := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(v, b)
	return v
}

// parseProof also rejects a non-canonical Gamma encoding, which draft03.ParseProof accepts
// but Algorand's libsodium (and so the AVM) rejects.
func parseProof(b []byte) (draft03.Proof, error) {
	gamma, err := new(edwards25519.Point).SetBytes(b[:32])
	if err != nil {
		return draft03.Proof{}, err
	}
	if !bytes.Equal(gamma.Bytes(), b[:32]) {
		return draft03.Proof{}, errors.New("non-canonical Gamma encoding")
	}
	return draft03.ParseProof(b)
}

// export returns {value} or {error}; recovering panics keeps one bad call from exiting the Go runtime.
func export(fn func(args []js.Value) ([]byte, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) (result any) {
		defer func() {
			if r := recover(); r != nil {
				result = map[string]any{"error": fmt.Sprint(r)}
			}
		}()
		out, err := fn(args)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"value": bytesToJS(out)}
	})
}

func main() {
	js.Global().Set("algoVrf", map[string]any{
		// prove(secretKey, message) -> proof
		"prove": export(func(args []js.Value) ([]byte, error) {
			sk := draft03.PrivateKey(bytesFromJS(args[0]))
			proof, err := sk.Prove(bytesFromJS(args[1]))
			return proof[:], err
		}),
		// verify(publicKey, message, proof) -> output
		"verify": export(func(args []js.Value) ([]byte, error) {
			pk, err := draft03.ParsePublicKey(bytesFromJS(args[0]))
			if err != nil {
				return nil, err
			}
			proof, err := parseProof(bytesFromJS(args[2]))
			if err != nil {
				return nil, err
			}
			output, err := draft03.Verify(pk, bytesFromJS(args[1]), proof)
			return output[:], err
		}),
		// proofToHash(proof) -> output
		"proofToHash": export(func(args []js.Value) ([]byte, error) {
			proof, err := parseProof(bytesFromJS(args[0]))
			if err != nil {
				return nil, err
			}
			output, err := proof.Hash()
			return output[:], err
		}),
	})
	select {}
}

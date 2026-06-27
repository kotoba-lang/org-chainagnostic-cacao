# cacao-clj

**CAIP-122 / SIWE (EIP-4361) CACAO mint + verify in pure Clojure.** A CACAO is a
self-sovereign, signed, expiring capability — a SIWE plaintext carrying an issuer
DID, an audience, a nonce/expiry and a `resources` grant, serialized as CBOR
(`{h,p,s}`) and Ed25519-signed. It's the **no-server-key** authorization for
kotoba / kotobase (datom-transact leashes, `kotobase:pin`, …): minted in the
holder's OWN runtime, presented as an opaque `cacao_b64`, never a platform key.

```clojure
(require '[cacao.core :as cacao])

(def c (cacao/mint
         {:seed seed-bytes                 ; raw 32-byte Ed25519 seed; iss = its did:key
          :aud "did:key:zNODE"
          :iat "2026-06-27T00:00:00Z" :exp "2026-07-27T00:00:00Z" :nonce "n1"
          :resources ["kotoba://can/kotobase:pin" "kotoba://graph/did:key:z…"]}))
;; => {:cacao-b64 "…" :iss "did:key:z6Mk…" :siwe "…"}

(cacao/verify (:cacao-b64 c))      ;=> {:valid? true :iss "did:key:z6Mk…" :payload {…}}
(cacao/auth-header c)              ;=> {:authorization "CACAO …" :x-kotoba-did "did:key:z6Mk…"}
```

- **`mint`** derives `iss` from the seed (issuer binding — you never pass it),
  builds the canonical SIWE plaintext, signs it, and emits the CBOR CACAO. The
  `p` field order is signature-significant, so the CBOR is order-preserving.
- **`verify`** decodes, reconstructs the SIWE plaintext, and checks the EdDSA
  signature under the issuer did:key. Exception-safe — malformed input → `{:valid? false}`.
- **`auth-header`** gives the `Authorization: CACAO …` + `x-kotoba-did` headers.

Built on **com-junkawasaki/ed25519-clj** (sign / did:key) +
**com-junkawasaki/dag-cbor-clj** (order-preserving CBOR). No native deps,
babashka-friendly.

## Correctness

`bb test`: mint→verify round-trip + issuer binding, tamper rejection,
SIWE plaintext shape, header shape → 4 tests / 31 assertions green.

## License

Apache-2.0.

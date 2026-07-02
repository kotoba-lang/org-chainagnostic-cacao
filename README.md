# cacao-clj

[![CI](https://github.com/kotoba-lang/cacao/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/cacao/actions/workflows/ci.yml)

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

## Delegation chains — `verify-chain`

`verify-chain` verifies an ORDERED delegation chain — a vector of `cacao_b64`
strings, root first, leaf last. Each link is a CACAO whose `aud` names the
delegate; that delegate re-issues the next link with its own key:

```clojure
(cacao/verify-chain [root-b64 mid-b64 leaf-b64] {:now "2026-07-02T00:00:00Z"})
;; => {:chain/valid? true
;;     :chain/problems []
;;     :chain/root-iss "did:key:z6Mk…"        ; root issuer (the delegating authority)
;;     :chain/holder "did:key:z6Mk…"          ; leaf aud (who may present the chain)
;;     :chain/resources #{"kotoba://cap/host/ledger-append/ledger:main"}
;;     :chain/expires "2026-07-10T00:00:00Z"  ; min exp across the chain
;;     :chain/depth 3}
```

Chain validity requires, per link and per parent→child pair:

- **signature**: every link verifies under its own issuer did:key (`verify`);
- **linkage**: child `iss` == parent payload `aud` — the delegate re-issues;
- **attenuation**: child `resources` ⊆ parent `resources` under `covers?` —
  exact string match, or a parent trailing-`*` wildcard
  (`kotoba://cap/<kind>/*` covers `kotoba://cap/<kind>/<r>`). A child may only
  narrow, never escalate;
- **expiry ordering**: child `exp` <= parent `exp` when both are present;
- **freshness** (optional `:now`): every link satisfies `iat <= now < exp`
  (each bound enforced when the field is present), so expired or
  not-yet-valid links reject the chain.

On failure the result is `{:chain/valid? false :chain/problems [...]}` with
per-link problem maps (`:chain/invalid-signature`, `:chain/broken-linkage`,
`:chain/resource-escalation`, `:chain/expiry-extended`, `:chain/expired`,
`:chain/not-yet-valid`, `:chain/malformed-input`). Malformed input never
throws. `:chain/resources` is the LEAF's effective resource set — the
narrowest scope in the chain — which downstream (crypto-free) layers such as
`kotoba.lang.capability-cacao` map to capability grants.

Built on **com-junkawasaki/ed25519-clj** (sign / did:key) +
**com-junkawasaki/dag-cbor-clj** (order-preserving CBOR). No native deps,
babashka-friendly.

## Correctness

`bb test` / `clojure -M:test`: mint→verify round-trip + issuer binding, tamper
rejection, SIWE plaintext shape, header shape, plus the delegation-chain suite
(real minted 2- and 3-link chains, tampered middle link, resource escalation,
expiry ordering, broken iss/aud linkage, `:now` freshness, malformed input)
→ 14 tests / 89 assertions green.

## License

Apache-2.0.

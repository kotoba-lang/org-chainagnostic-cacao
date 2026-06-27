;; cacao.core — CAIP-122 / SIWE (EIP-4361) CACAO mint + verify, pure Clojure.
;;
;; A CACAO is a self-sovereign, signed, expiring capability: a SIWE plaintext
;; carrying an issuer DID, an audience, a nonce/expiry, and a `resources` grant,
;; serialized as definite-length CBOR ({h,p,s}) and signed with Ed25519. Used as
;; the no-server-key authorization for kotoba/kotobase (datom:transact leashes,
;; `kotobase:pin`, …) — minted in the holder's OWN runtime, presented as an opaque
;; `cacao_b64`, never a platform-held key.
;;
;; This packages the format that was hand-rolled inline (the ibuki/kaname leash
;; issuer, the kotobase pin client): one `mint` + one `verify`, built on
;; com-junkawasaki/ed25519-clj (sign/derive) + com-junkawasaki/dag-cbor-clj
;; (order-preserving CBOR — the p-field order is signature-significant).
;;
;;   (require '[cacao.core :as cacao])
;;   (cacao/mint {:seed seed-bytes :aud node-did :nonce "n1"
;;                :iat "2026-06-27T00:00:00Z" :exp "2026-07-27T00:00:00Z"
;;                :resources ["kotoba://can/kotobase:pin" (str "kotoba://graph/" did)]})
;;   ;=> {:cacao-b64 "…" :iss "did:key:z6Mk…" :siwe "…"}
;;   (cacao/verify cacao-b64)  ;=> {:valid? true :iss "did:key:z6Mk…" :payload {…}}
(ns cacao.core
  (:require [clojure.string :as str]
            [ed25519.core :as ed]
            [cbor.core :as cbor])
  (:import (java.util Base64)))

(defn- b64 ^String [^bytes b] (.encodeToString (Base64/getEncoder) b))
(defn- unb64 ^bytes [^String s] (.decode (Base64/getDecoder) s))

(defn siwe-message
  "The EIP-4361 plaintext that gets signed. `iss` must be a did:key (the address
   is its last ':'-segment). Fields are emitted in the canonical SIWE line order."
  ^String [{:keys [iss aud iat exp nonce domain version statement resources]}]
  (let [addr (last (str/split iss #":"))
        lines (cond-> [(str domain " wants you to sign in with your Ethereum account:")
                       addr ""]
                statement     (conj statement "")
                :always       (into [(str "URI: " aud)
                                     (str "Version: " version)
                                     "Chain ID: 1"
                                     (str "Nonce: " nonce)
                                     (str "Issued At: " iat)])
                exp           (conj (str "Expiration Time: " exp))
                (seq resources) (conj "Resources:")
                (seq resources) (into (map #(str "- " %) resources)))]
    (str/join "\n" lines)))

(defn mint
  "Mint a CACAO signed with a raw 32-byte Ed25519 seed. `iss` is DERIVED from the
   seed (issuer binding) — never passed in. Returns {:cacao-b64 :iss :siwe}.
   Required opts: :seed :aud :iat :exp :nonce :resources. Optional: :domain
   (default kotoba.etzhayyim.com) :version (default \"1\") :statement."
  [{:keys [seed aud iat exp nonce resources statement domain version]
    :or {domain "kotoba.etzhayyim.com" version "1"}}]
  (let [iss (ed/did-key-from-seed seed)
        msg (siwe-message {:iss iss :aud aud :iat iat :exp exp :nonce nonce
                           :domain domain :version version :statement statement
                           :resources resources})
        sig-b64 (b64 (ed/sign seed (.getBytes msg "UTF-8")))
        cacao (cbor/encode
               (cbor/ordered
                [["h" (cbor/ordered [["t" "eip4361"]])]
                 ["p" (cbor/ordered [["iss" iss] ["aud" aud] ["iat" iat] ["exp" exp]
                                     ["nonce" nonce] ["domain" domain] ["version" version]
                                     ["resources" (vec resources)]])]
                 ["s" (cbor/ordered [["t" "EdDSA"] ["s" sig-b64]])]]))]
    {:cacao-b64 (b64 cacao) :iss iss :siwe msg}))

(defn verify
  "Verify a base64 CACAO: decode the CBOR, reconstruct the SIWE plaintext from
   `p`, and check the EdDSA signature under the issuer did:key (issuer binding).
   Returns {:valid? bool :iss did :payload {…}}."
  [^String cacao-b64]
  (try
    (let [m (cbor/decode (unb64 cacao-b64))
          p (get m "p") s (get m "s")
          iss (get p "iss")
          sig (unb64 (get s "s"))
          payload {:iss iss :aud (get p "aud") :iat (get p "iat") :exp (get p "exp")
                   :nonce (get p "nonce") :domain (get p "domain")
                   :version (get p "version") :resources (get p "resources")}
          valid? (ed/verify-did iss (.getBytes (siwe-message payload) "UTF-8") sig)]
      {:valid? valid? :iss iss :payload payload})
    (catch Exception _ {:valid? false})))

(defn auth-header
  "Build the Authorization header value + the x-kotoba-did sidecar for a kotobase
   /pins or kotoba xrpc call: {:authorization \"CACAO <b64>\" :x-kotoba-did <iss>}."
  [{:keys [cacao-b64 iss]}]
  {:authorization (str "CACAO " cacao-b64) :x-kotoba-did iss})

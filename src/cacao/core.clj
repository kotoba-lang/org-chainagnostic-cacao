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
;;
;;   ;; nonce-replay protection: hold on to a store across calls to actually
;;   ;; reject a replayed CACAO (see `verify`'s :nonce-store doc for why the
;;   ;; default, store-omitted arity can't do this on its own).
;;   (def store (cacao/fresh-nonce-store))
;;   (cacao/verify cacao-b64 {:nonce-store store})  ;=> {:valid? true ...}
;;   (cacao/verify cacao-b64 {:nonce-store store})  ;=> {:valid? false ...} (replay)
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
  (when (nil? nonce)
    (throw (ex-info "cacao/mint: :nonce is required — verify/verify-chain's
                     nonce-replay protection has no effect on a CACAO minted
                     without one (a nonce-less payload is treated as
                     un-dedupeable, not as replay-safe)"
                    {:aud aud})))
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

(defn- temporal-ok?
  "true iff `now` (when given) falls within [iat, exp) of `payload`, each
   bound enforced only when the corresponding field is present. Mirrors
   verify-chain's own per-link temporal-problems logic exactly (iat <= now
   < exp), so a single verify and a chained verify-chain reject the same
   expired/not-yet-valid CACAO the same way."
  [{:keys [iat exp]} now]
  (or (nil? now)
      (and (or (nil? iat) (not (pos? (compare iat now))))
           (or (nil? exp) (neg? (compare now exp))))))

;; ── nonce-replay protection ─────────────────────────────────────────────────
;;
;; SECURITY FIX: `verify`/`verify-chain` mint/embed a `nonce` (see `mint`,
;; `siwe-message`) but, until this addition, NEVER checked it against
;; anything — a valid, unexpired CACAO captured anywhere (logs, network
;; transit, a compromised intermediate) could be replayed verbatim any
;; number of times until its `exp`. The old Rust implementation of this same
;; trust boundary had a sharded NonceStore for exactly this (see
;; kotoba-lang/kotoba CLAUDE.md: "NonceStore: RwLock<HashMap> → DashMap", a
;; 64-way sharded in-memory nonce table with a bounded MAX_NONCES and
;; expiry-driven eviction); that protection was lost when the Rust code was
;; retired in favor of this Clojure reimplementation, which never replaced
;; it. This closes that gap.
;;
;; This is a LIBRARY, not a service: callers range from a one-shot CLI
;; invocation (`kotoba run --cacao`) to a long-running server. So the store
;; is caller-pluggable — `NonceStore` is a two-line protocol, not a
;; hardcoded implementation — and this library only owns the check/record
;; CONTRACT, never where (if anywhere) it's persisted. A plain Clojure atom
;; satisfies the protocol out of the box (in-memory, single-process); a host
;; wanting cross-process / cross-restart protection extends the protocol
;; on its own durable type (Redis, a DB row with a UNIQUE constraint, …) and
;; passes an instance of it via the `:nonce-store` opt.
;;
;; The key checked/recorded is always the 2-vector `[iss nonce]`, never the
;; bare nonce string: a nonce is only meaningful scoped to the issuer that
;; chose it (mint doesn't coordinate nonces across issuers), so two
;; DIFFERENT issuers coincidentally minting with the same nonce string is
;; not a replay and must not collide in the store.

(defprotocol NonceStore
  "A guard against CACAO replay. `check-and-record!` MUST be a single atomic
   test-and-set — test whether REPLAY-KEY (a `[iss nonce]` vector) has been
   seen before and, if not, record it as seen, in one indivisible step. (A
   separate `seen?` + `record!` pair would TOCTOU-race: two concurrent
   callers could both observe \"not seen\" and both proceed.) Returns:

     true  — REPLAY-KEY was fresh (not seen before) and is now recorded;
             the caller should treat the CACAO as not-a-replay.
     false — REPLAY-KEY was already recorded; the caller MUST reject (this
             is either a genuine replay, or two independent CACAOs that
             happen to share both `iss` and `nonce`, which mint never
             promises won't happen if the caller reuses nonces)."
  (check-and-record! [store replay-key]))

(extend-protocol NonceStore
  clojure.lang.Atom
  (check-and-record! [store replay-key]
    ;; swap-vals! is a single atomic operation: the returned `old` is
    ;; guaranteed to be the pre-swap value actually observed by THIS swap,
    ;; so `contains?` on it is race-free (unlike a separate deref + swap!).
    (let [[old _new] (swap-vals! store conj replay-key)]
      (not (contains? old replay-key)))))

(defn fresh-nonce-store
  "A fresh, empty, in-memory NonceStore: an atom over a set of `[iss nonce]`
   keys. Thread-safe for concurrent callers WITHIN one process (backed by
   swap-vals!, atomic) but pure in-memory state — NOT persisted, NOT shared
   across processes, and gone the moment this atom is garbage-collected.
   `verify`/`verify-chain` call this to synthesize a THROWAWAY store when the
   caller doesn't pass `:nonce-store`; keep a reference to one yourself (or
   your own NonceStore impl) and pass it explicitly for real replay
   protection across calls."
  [] (atom #{}))

(defn verify
  "Verify a base64 CACAO: decode the CBOR, reconstruct the SIWE plaintext from
   `p`, and check the EdDSA signature under the issuer did:key (issuer
   binding). OPTS may carry:

     `:now`          an ISO-8601 instant string; when given, the CACAO must
                      also satisfy iat <= now < exp (each bound enforced
                      when the field is present) — an expired or
                      not-yet-valid CACAO is rejected, the same way
                      verify-chain's :now option already rejects an
                      expired/not-yet-valid link (confirmed bug this closed:
                      without :now, a CACAO minted with any :exp, however
                      long past, verified true forever — a captured
                      single-token CACAO could be replayed indefinitely).

     `:nonce-store`  a NonceStore (see that protocol + `fresh-nonce-store`)
                      used to reject a REPLAYED CACAO: once a CACAO's
                      `[iss nonce]` has been recorded as seen against
                      STORE, presenting that same CACAO (or any other CACAO
                      sharing that iss+nonce) again is rejected. Only
                      recorded when the CACAO is otherwise fully valid (sig
                      + temporal) — an invalid/tampered CACAO can't be used
                      to pre-emptively burn a nonce that hasn't really been
                      used yet. When OMITTED, a FRESH throwaway store
                      (`fresh-nonce-store`) is used for this call only:
                      this can never reject anything (there is nothing it
                      could have seen before) and provides NO real replay
                      protection across calls — it exists only so this
                      arity stays crash-free for callers that haven't wired
                      up a store yet. Pass a store you retain across calls
                      (module-level, request-scoped, or a durable NonceStore
                      impl) for actual protection; see the CACAO README's
                      nonce-replay section.

   Returns {:valid? bool :iss did :payload {…}}."
  ([cacao-b64] (verify cacao-b64 nil))
  ([^String cacao-b64 {:keys [now nonce-store]}]
   (try
     (let [m (cbor/decode (unb64 cacao-b64))
           p (get m "p") s (get m "s")
           iss (get p "iss")
           sig (unb64 (get s "s"))
           payload {:iss iss :aud (get p "aud") :iat (get p "iat") :exp (get p "exp")
                    :nonce (get p "nonce") :domain (get p "domain")
                    :version (get p "version") :resources (get p "resources")}
           sig-valid? (ed/verify-did iss (.getBytes (siwe-message payload) "UTF-8") sig)
           temporal-valid? (temporal-ok? payload now)]
       (if (and sig-valid? temporal-valid?)
         (let [nonce (:nonce payload)
               store (or nonce-store (fresh-nonce-store))
               ;; no :nonce on the payload → nothing to dedupe on, treat as
               ;; not-a-replay (mint always sets one; this only matters for
               ;; a hand-crafted CACAO that omits it).
               fresh? (or (nil? nonce) (check-and-record! store [iss nonce]))]
           {:valid? fresh? :iss iss :payload payload})
         {:valid? false :iss iss :payload payload}))
     (catch Exception _ {:valid? false}))))

;; ── delegation chains ─────────────────────────────────────────────────────────

(defn covers?
  "True when PARENT resource string covers CHILD. A parent ending in `*` is a
   trailing wildcard and covers every child sharing the prefix before the `*`
   (e.g. \"kotoba://cap/graph-read/*\" covers \"kotoba://cap/graph-read/g1\");
   otherwise the match must be exact."
  [parent child]
  (and (string? parent) (string? child)
       (if (str/ends-with? parent "*")
         (str/starts-with? child (subs parent 0 (dec (count parent))))
         (= parent child))))

(defn- signature-problems [links]
  (keep-indexed (fn [i l]
                  (when-not (:valid? l)
                    {:problem :chain/invalid-signature :index i}))
                links))

(defn- temporal-problems
  "iat <= now < exp for every link, each bound checked when the field is present."
  [payloads now]
  (when now
    (for [[i {:keys [iat exp]}] (map-indexed vector payloads)
          problem [(when (and iat (pos? (compare iat now)))
                     {:problem :chain/not-yet-valid :index i :iat iat :now now})
                   (when (and exp (not (neg? (compare now exp))))
                     {:problem :chain/expired :index i :exp exp :now now})]
          :when problem]
      problem)))

(defn- link-problems
  "Parent→child constraints for the pair ending at index CI."
  [parent child ci]
  (let [uncovered (seq (remove (fn [r] (some #(covers? % r) (:resources parent)))
                               (:resources child)))]
    (filter some?
            [(when (or (nil? (:iss child)) (not= (:iss child) (:aud parent)))
               {:problem :chain/broken-linkage :index ci
                :expected (:aud parent) :got (:iss child)})
             (when uncovered
               {:problem :chain/resource-escalation :index ci
                :resources (vec uncovered)})
             (when (and (:exp parent) (:exp child)
                        (pos? (compare (:exp child) (:exp parent))))
               {:problem :chain/expiry-extended :index ci
                :parent-exp (:exp parent) :child-exp (:exp child)})])))

(defn- nonce-problems
  "Nonce-replay problems across the chain's LINKS/PAYLOADS, checked against
   STORE — the SAME store instance for every link of this one verify-chain
   call (see verify-chain's :nonce-store opt), so two links of the SAME
   chain that share an `[iss nonce]` are caught too, not only replay across
   separate verify-chain calls. Only checked for a link whose own signature
   already verified (`(:valid? (links i))`) AND whose temporal bounds are
   satisfied at NOW (`temporal-ok?`, same iat<=now<exp rule
   `temporal-problems` enforces): an unsigned/tampered link's `nonce` field
   isn't authentic (nonce lives inside the signed SIWE plaintext) and must
   not be allowed to burn a real one — see `verify`'s own :nonce-store
   gating for the same rationale. The temporal half of this gate matters
   because `links` (built by `verify-chain` via a bare, no-`:now` `verify`
   call per link) only reflects SIGNATURE validity, never temporal
   validity — without checking `temporal-ok?` here too, a validly-signed
   but not-yet-valid or already-expired link would still burn its nonce
   against the real STORE (even though the overall chain is correctly
   rejected via `temporal-problems`), permanently locking out the
   legitimate holder from ever presenting that same chain again once it
   actually becomes valid."
  [links payloads store now]
  (keep-indexed
   (fn [i {:keys [iss nonce] :as payload}]
     (when (and nonce
                (:valid? (nth links i))
                (temporal-ok? payload now)
                (not (check-and-record! store [iss nonce])))
       {:problem :chain/nonce-replay :index i :nonce nonce}))
   payloads))

(defn verify-chain
  "Verify an ordered CACAO delegation chain (root first, leaf last), given as a
   vector of base64 CACAO strings. Chain validity requires:

   - every link's EdDSA signature verifies (see `verify`);
   - for each parent→child pair the child is re-issued by the parent's
     delegate: child `iss` == parent payload `aud`;
   - the child's `resources` are a subset of the parent's under `covers?`
     (exact string match, or a parent trailing-`*` wildcard);
   - child `exp` <= parent `exp` when both are present;
   - no link's `[iss nonce]` has been seen before, per `:nonce-store` (see
     below) — a replayed link rejects the whole chain.

   OPTS may carry:

     `:now`          an ISO-8601 instant string; when given, every link must
                      satisfy iat <= now < exp (each bound enforced when the
                      field is present), so expired or not-yet-valid links
                      reject the chain.

     `:nonce-store`  a NonceStore (see that protocol + `fresh-nonce-store`
                      in this ns) checked/recorded for every link's
                      `[iss nonce]`. When OMITTED, a FRESH throwaway store
                      is synthesized for JUST this call: it still catches
                      two links of the SAME chain sharing an iss+nonce, but
                      — being discarded when the call returns — provides NO
                      protection against the same chain (or a link from it)
                      being presented again in a LATER verify-chain call.
                      Pass a store you retain across calls for that; see
                      the CACAO README's nonce-replay section. (This is the
                      same fresh-per-call fallback `verify` uses, and the
                      same caveat applies.)

   Returns {:chain/valid? bool :chain/problems [{:problem ..} ...]
            :chain/root-iss <root issuer did> :chain/holder <leaf aud>
            :chain/resources <leaf's effective resource set>
            :chain/expires <min exp across the chain, or nil>
            :chain/depth <link count>}.
   Malformed input never throws — it yields {:chain/valid? false ...}."
  ([chain] (verify-chain chain nil))
  ([chain {:keys [now nonce-store]}]
   (try
     (if-not (and (sequential? chain) (seq chain) (every? string? chain))
       {:chain/valid? false
        :chain/problems [{:problem :chain/malformed-input}]
        :chain/root-iss nil :chain/holder nil :chain/resources #{}
        :chain/expires nil
        :chain/depth (if (sequential? chain) (count chain) 0)}
       (let [links (mapv verify chain)
             payloads (mapv :payload links)
             store (or nonce-store (fresh-nonce-store))
             problems (vec (concat (signature-problems links)
                                   (temporal-problems payloads now)
                                   (nonce-problems links payloads store now)
                                   (mapcat (fn [i]
                                             (link-problems (payloads i)
                                                            (payloads (inc i))
                                                            (inc i)))
                                           (range (dec (count payloads))))))
             leaf (peek payloads)]
         {:chain/valid? (empty? problems)
          :chain/problems problems
          :chain/root-iss (:iss (first payloads))
          :chain/holder (:aud leaf)
          :chain/resources (set (:resources leaf))
          :chain/expires (first (sort (keep :exp payloads)))
          :chain/depth (count chain)}))
     (catch Exception e
       {:chain/valid? false
        :chain/problems [{:problem :chain/error :message (.getMessage e)}]
        :chain/root-iss nil :chain/holder nil :chain/resources #{}
        :chain/expires nil :chain/depth 0}))))

(defn auth-header
  "Build the Authorization header value + the x-kotoba-did sidecar for a kotobase
   /pins or kotoba xrpc call: {:authorization \"CACAO <b64>\" :x-kotoba-did <iss>}."
  [{:keys [cacao-b64 iss]}]
  {:authorization (str "CACAO " cacao-b64) :x-kotoba-did iss})

(ns cacao.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [cacao.core :as cacao]
            [ed25519.core :as ed])
  (:import (java.security KeyPairGenerator)
           (java.util Base64)))

(defn- seed [] (byte-array (take-last 32 (seq (.getEncoded (.getPrivate
                 (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))))))))

(def ^:private opts-for
  (fn [s] {:seed s :aud "did:key:zAUD" :iat "2026-06-27T00:00:00Z"
           :exp "2026-07-27T00:00:00Z" :nonce "n1"
           :resources ["kotoba://can/kotobase:pin" "kotoba://graph/g"]}))

(deftest mint-verify-roundtrip
  (dotimes [_ 6]
    (let [s (seed)
          {:keys [cacao-b64 iss]} (cacao/mint (opts-for s))
          v (cacao/verify cacao-b64)]
      (is (= iss (ed/did-key-from-seed s)) "iss is derived from the seed (issuer binding)")
      (is (true? (:valid? v)))
      (is (= iss (:iss v)))
      (is (= ["kotoba://can/kotobase:pin" "kotoba://graph/g"] (:resources (:payload v)))))))

(deftest mint-requires-a-nonce
  ;; mint's own docstring lists :nonce as "Required" -- this proves it's
  ;; actually enforced: a CACAO minted without one has no replay protection
  ;; at all (verify/verify-chain's `(or (nil? nonce) ...)` fallback treats a
  ;; nonce-less payload as un-dedupeable, not as replay-safe), so silently
  ;; allowing a nonce-less mint would be a footgun.
  (is (thrown? clojure.lang.ExceptionInfo
               (cacao/mint (dissoc (opts-for (seed)) :nonce)))))

(deftest tamper-is-rejected
  (let [{:keys [cacao-b64]} (cacao/mint (opts-for (seed)))
        m (cacao/verify cacao-b64)]
    (is (true? (:valid? m)))
    ;; flip a byte in the signature → invalid
    (let [raw (.decode (Base64/getDecoder) cacao-b64)
          _ (aset-byte raw (dec (count raw)) (unchecked-byte (bit-xor (aget raw (dec (count raw))) 1)))
          tampered (.encodeToString (Base64/getEncoder) raw)]
      (is (false? (:valid? (cacao/verify tampered)))))))

(deftest verify-without-now-does-not-check-expiry-unchanged-behavior
  (let [{:keys [cacao-b64]} (cacao/mint (opts-for (seed)))]
    (is (true? (:valid? (cacao/verify cacao-b64))) "1-arity call is unaffected by the :now feature")))

(deftest verify-now-rejects-expired-and-not-yet-valid-cacaos
  ;; CONFIRMED BUG regression: verify had no expiry-checking capability at
  ;; all -- a CACAO with any :exp, however long past, verified true forever.
  (let [s (seed)
        {:keys [cacao-b64]} (cacao/mint {:seed s :aud "did:key:zAUD"
                                         :iat "2026-06-27T00:00:00Z"
                                         :exp "2026-07-27T00:00:00Z"
                                         :nonce "n1" :resources ["r1"]})]
    (testing "now within [iat, exp) verifies"
      (is (true? (:valid? (cacao/verify cacao-b64 {:now "2026-07-01T00:00:00Z"})))))
    (testing "now == exp is already expired (iat <= now < exp)"
      (is (false? (:valid? (cacao/verify cacao-b64 {:now "2026-07-27T00:00:00Z"})))))
    (testing "now well past exp is expired"
      (is (false? (:valid? (cacao/verify cacao-b64 {:now "2030-01-01T00:00:00Z"})))))
    (testing "before iat the CACAO is not yet valid"
      (is (false? (:valid? (cacao/verify cacao-b64 {:now "2026-06-01T00:00:00Z"})))))
    (testing "a tampered signature is still rejected even with a valid :now"
      (let [raw (.decode (Base64/getDecoder) cacao-b64)
            _ (aset-byte raw (dec (count raw)) (unchecked-byte (bit-xor (aget raw (dec (count raw))) 1)))
            tampered (.encodeToString (Base64/getEncoder) raw)]
        (is (false? (:valid? (cacao/verify tampered {:now "2026-07-01T00:00:00Z"}))))))))

;; ── nonce-replay protection ─────────────────────────────────────────────────

(deftest fresh-nonce-never-seen-verifies-and-gets-recorded
  (let [store (cacao/fresh-nonce-store)
        {:keys [cacao-b64 iss]} (cacao/mint (opts-for (seed)))]
    (is (true? (:valid? (cacao/verify cacao-b64 {:nonce-store store})))
        "a never-before-seen nonce verifies")
    (is (contains? @store [iss "n1"]) "and the [iss nonce] is now recorded")))

(deftest replayed-cacao-is-rejected-by-same-store
  (let [store (cacao/fresh-nonce-store)
        {:keys [cacao-b64]} (cacao/mint (opts-for (seed)))]
    (is (true? (:valid? (cacao/verify cacao-b64 {:nonce-store store})))
        "first presentation succeeds")
    (is (false? (:valid? (cacao/verify cacao-b64 {:nonce-store store})))
        "SAME cacao-b64 presented again against the SAME store is a replay")
    (is (false? (:valid? (cacao/verify cacao-b64 {:nonce-store store})))
        "and stays rejected on a third presentation")))

(deftest two-different-cacaos-both-succeed-against-same-store
  (let [store (cacao/fresh-nonce-store)
        s (seed)
        c1 (cacao/mint (assoc (opts-for s) :nonce "nonce-1"))
        c2 (cacao/mint (assoc (opts-for s) :nonce "nonce-2"))]
    (is (true? (:valid? (cacao/verify (:cacao-b64 c1) {:nonce-store store})))
        "first distinct-nonce CACAO verifies")
    (is (true? (:valid? (cacao/verify (:cacao-b64 c2) {:nonce-store store})))
        "second distinct-nonce CACAO ALSO verifies — not over-broadly rejected")
    ;; and now replaying either of them against the same store fails
    (is (false? (:valid? (cacao/verify (:cacao-b64 c1) {:nonce-store store}))))
    (is (false? (:valid? (cacao/verify (:cacao-b64 c2) {:nonce-store store}))))))

(deftest different-issuers-sharing-a-nonce-string-is-not-a-collision
  ;; the replay key is [iss nonce], not the bare nonce — two independent
  ;; issuers minting with the same nonce string coincidentally must not
  ;; collide in the store.
  (let [store (cacao/fresh-nonce-store)
        c1 (cacao/mint (opts-for (seed)))
        c2 (cacao/mint (opts-for (seed)))]
    (is (true? (:valid? (cacao/verify (:cacao-b64 c1) {:nonce-store store}))))
    (is (true? (:valid? (cacao/verify (:cacao-b64 c2) {:nonce-store store})))
        "different iss, same literal nonce \"n1\" — not a replay")))

(deftest tampered-cacao-does-not-burn-the-nonce
  ;; a signature-invalid presentation must not consume the nonce store slot —
  ;; otherwise an attacker forging a bogus CACAO with a guessed/observed
  ;; nonce could pre-emptively burn a nonce the real holder hasn't used yet.
  (let [store (cacao/fresh-nonce-store)
        {:keys [cacao-b64]} (cacao/mint (opts-for (seed)))
        raw (.decode (Base64/getDecoder) cacao-b64)
        _ (aset-byte raw (dec (count raw)) (unchecked-byte (bit-xor (aget raw (dec (count raw))) 1)))
        tampered (.encodeToString (Base64/getEncoder) raw)]
    (is (false? (:valid? (cacao/verify tampered {:nonce-store store}))) "tampered sig rejected")
    (is (true? (:valid? (cacao/verify cacao-b64 {:nonce-store store})))
        "the REAL cacao still verifies afterwards — the tamper attempt didn't burn the nonce")))

(deftest default-fresh-store-per-call-does-not-crash-but-cannot-protect-across-calls
  ;; documents the deliberate limitation: omitting :nonce-store synthesizes a
  ;; THROWAWAY store for that single verify call, so it can never observe a
  ;; nonce from a PRIOR call — this proves the fallback path is functional
  ;; (no exception, still verifies true) and proves — by replaying the exact
  ;; same cacao-b64 twice with no store supplied — that it does NOT protect
  ;; across separate calls (both calls succeed, unlike the store-supplied
  ;; replay test above where the second call is rejected).
  (let [{:keys [cacao-b64]} (cacao/mint (opts-for (seed)))]
    (is (true? (:valid? (cacao/verify cacao-b64))) "1-arity (no opts) still works")
    (is (true? (:valid? (cacao/verify cacao-b64 {}))) "2-arity with no :nonce-store still works")
    (is (true? (:valid? (cacao/verify cacao-b64 {})))
        (str "replaying the SAME cacao-b64 a second time with no store ALSO verifies true — "
             "proof the default fallback provides no cross-call replay protection"))))

(deftest siwe-shape
  (let [s (seed) iss (ed/did-key-from-seed s)
        msg (cacao/siwe-message {:iss iss :aud "did:key:zAUD" :iat "T0" :exp "T1"
                                 :nonce "n1" :domain "kotobase.net" :version "1"
                                 :resources ["r1" "r2"]})]
    (is (clojure.string/includes? msg "kotobase.net wants you to sign in"))
    (is (clojure.string/includes? msg "Chain ID: 1"))
    (is (clojure.string/includes? msg "Resources:\n- r1\n- r2"))))

(deftest auth-header-shape
  (let [b (cacao/mint (opts-for (seed)))
        h (cacao/auth-header b)]
    (is (clojure.string/starts-with? (:authorization h) "CACAO "))
    (is (= (:iss b) (:x-kotoba-did h)))))

;; ── delegation chains ─────────────────────────────────────────────────────────

;; Deterministic seeds so the chain fixtures are reproducible run to run.
(def ^:private seed-a (byte-array (range 0 32)))
(def ^:private seed-b (byte-array (range 32 64)))
(def ^:private seed-c (byte-array (range 64 96)))

(def ^:private did-a (ed/did-key-from-seed seed-a))
(def ^:private did-b (ed/did-key-from-seed seed-b))
(def ^:private did-c (ed/did-key-from-seed seed-c))

(defn- mint-link
  [seed aud resources & [{:keys [iat exp nonce]}]]
  (:cacao-b64 (cacao/mint {:seed seed :aud aud
                           :iat (or iat "2026-06-27T00:00:00Z")
                           :exp (or exp "2026-07-27T00:00:00Z")
                           :nonce (or nonce "n1")
                           :resources resources})))

(def ^:private wildcard "kotoba://cap/host/ledger-append/*")
(def ^:private ledger-main "kotoba://cap/host/ledger-append/ledger:main")
(def ^:private ledger-aux "kotoba://cap/host/ledger-append/ledger:aux")

(deftest covers?-wildcard-rule
  (is (true? (cacao/covers? ledger-main ledger-main)) "exact match")
  (is (false? (cacao/covers? ledger-main ledger-aux)) "exact means exact")
  (is (true? (cacao/covers? wildcard ledger-main)) "trailing-* covers prefix")
  (is (true? (cacao/covers? wildcard wildcard)) "wildcard covers itself")
  (is (false? (cacao/covers? "kotoba://cap/graph-read/*"
                             "kotoba://cap/graph-write/g1"))
      "wildcard does not cross kinds")
  (is (false? (cacao/covers? "kotoba://cap/*x" "kotoba://cap/anything"))
      "* is only a wildcard in trailing position — here the parent literal prefix must match")
  (is (false? (cacao/covers? nil ledger-main)))
  (is (false? (cacao/covers? ledger-main 42))))

(deftest two-link-chain-verifies
  (let [root (mint-link seed-a did-b [wildcard ledger-aux])
        leaf (mint-link seed-b did-c [ledger-main])
        r (cacao/verify-chain [root leaf])]
    (is (true? (:chain/valid? r)))
    (is (= [] (:chain/problems r)))
    (is (= did-a (:chain/root-iss r)))
    (is (= did-c (:chain/holder r)))
    (is (= #{ledger-main} (:chain/resources r)) "leaf's effective resource set")
    (is (= "2026-07-27T00:00:00Z" (:chain/expires r)))
    (is (= 2 (:chain/depth r)))))

(deftest three-link-chain-verifies-and-takes-min-expiry
  (let [root (mint-link seed-a did-b [wildcard])
        mid (mint-link seed-b did-c [ledger-main ledger-aux]
                       {:exp "2026-07-20T00:00:00Z"})
        leaf (mint-link seed-c "did:key:zHOLDER" [ledger-main]
                        {:exp "2026-07-10T00:00:00Z"})
        r (cacao/verify-chain [root mid leaf])]
    (is (true? (:chain/valid? r)))
    (is (= did-a (:chain/root-iss r)))
    (is (= "did:key:zHOLDER" (:chain/holder r)))
    (is (= #{ledger-main} (:chain/resources r)))
    (is (= "2026-07-10T00:00:00Z" (:chain/expires r)) "min exp across the chain")
    (is (= 3 (:chain/depth r)))))

(deftest single-link-chain-is-a-depth-1-chain
  (let [r (cacao/verify-chain [(mint-link seed-a did-b [ledger-main])])]
    (is (true? (:chain/valid? r)))
    (is (= did-a (:chain/root-iss r)))
    (is (= did-b (:chain/holder r)))
    (is (= 1 (:chain/depth r)))))

(deftest tampered-middle-link-rejects-chain
  (let [root (mint-link seed-a did-b [wildcard])
        mid (mint-link seed-b did-c [ledger-main])
        leaf (mint-link seed-c "did:key:zHOLDER" [ledger-main])
        raw (.decode (Base64/getDecoder) mid)
        _ (aset-byte raw (dec (count raw))
                     (unchecked-byte (bit-xor (aget raw (dec (count raw))) 1)))
        tampered (.encodeToString (Base64/getEncoder) raw)
        r (cacao/verify-chain [root tampered leaf])]
    (is (false? (:chain/valid? r)))
    (is (some #(= {:problem :chain/invalid-signature :index 1} %)
              (:chain/problems r)))))

(deftest resource-escalation-rejects-chain
  (let [root (mint-link seed-a did-b [ledger-main])
        leaf (mint-link seed-b did-c [ledger-main ledger-aux])
        r (cacao/verify-chain [root leaf])]
    (is (false? (:chain/valid? r)))
    (is (= [{:problem :chain/resource-escalation :index 1
             :resources [ledger-aux]}]
           (:chain/problems r)))))

(deftest expiry-ordering-violation-rejects-chain
  (let [root (mint-link seed-a did-b [wildcard] {:exp "2026-07-10T00:00:00Z"})
        leaf (mint-link seed-b did-c [ledger-main] {:exp "2026-08-01T00:00:00Z"})
        r (cacao/verify-chain [root leaf])]
    (is (false? (:chain/valid? r)))
    (is (= [{:problem :chain/expiry-extended :index 1
             :parent-exp "2026-07-10T00:00:00Z"
             :child-exp "2026-08-01T00:00:00Z"}]
           (:chain/problems r)))))

(deftest wrong-iss-aud-linkage-rejects-chain
  (let [root (mint-link seed-a did-b [wildcard])
        ;; minted by C, but the parent delegated to B → iss != parent aud
        leaf (mint-link seed-c "did:key:zHOLDER" [ledger-main])
        r (cacao/verify-chain [root leaf])]
    (is (false? (:chain/valid? r)))
    (is (= [{:problem :chain/broken-linkage :index 1
             :expected did-b :got did-c}]
           (:chain/problems r)))))

(deftest now-rejects-expired-and-not-yet-valid-links
  (let [root (mint-link seed-a did-b [wildcard])
        leaf (mint-link seed-b did-c [ledger-main])
        chain [root leaf]]
    (is (true? (:chain/valid? (cacao/verify-chain chain {:now "2026-07-01T00:00:00Z"}))))
    (testing "now == exp is already expired (iat <= now < exp)"
      (let [r (cacao/verify-chain chain {:now "2026-07-27T00:00:00Z"})]
        (is (false? (:chain/valid? r)))
        (is (every? #(= :chain/expired (:problem %)) (:chain/problems r)))
        (is (= [0 1] (mapv :index (:chain/problems r))))))
    (testing "before iat the link is not yet valid"
      (let [r (cacao/verify-chain chain {:now "2026-06-01T00:00:00Z"})]
        (is (false? (:chain/valid? r)))
        (is (every? #(= :chain/not-yet-valid (:problem %)) (:chain/problems r)))))
    (testing "without :now no temporal check runs"
      (is (true? (:chain/valid? (cacao/verify-chain chain)))))))

;; ── chain-level nonce-replay protection ──────────────────────────────────────

(deftest replayed-chain-is-rejected-by-same-store
  (let [store (cacao/fresh-nonce-store)
        root (mint-link seed-a did-b [wildcard])
        leaf (mint-link seed-b did-c [ledger-main])
        chain [root leaf]]
    (is (true? (:chain/valid? (cacao/verify-chain chain {:nonce-store store})))
        "first presentation of the whole chain verifies")
    (let [r (cacao/verify-chain chain {:nonce-store store})]
      (is (false? (:chain/valid? r)) "SAME chain presented again against the SAME store is a replay")
      (is (every? #(= :chain/nonce-replay (:problem %)) (:chain/problems r)))
      (is (= [0 1] (mapv :index (:chain/problems r))) "both links are flagged as replayed"))))

(deftest two-different-chains-both-succeed-against-same-store
  (let [store (cacao/fresh-nonce-store)
        root1 (mint-link seed-a did-b [wildcard] {:nonce "root-nonce-1"})
        leaf1 (mint-link seed-b did-c [ledger-main] {:nonce "leaf-nonce-1"})
        root2 (mint-link seed-a did-b [wildcard] {:nonce "root-nonce-2"})
        leaf2 (mint-link seed-b did-c [ledger-main] {:nonce "leaf-nonce-2"})]
    (is (true? (:chain/valid? (cacao/verify-chain [root1 leaf1] {:nonce-store store}))))
    (is (true? (:chain/valid? (cacao/verify-chain [root2 leaf2] {:nonce-store store})))
        "a second chain with distinct nonces also verifies — not over-broadly rejected")))

(deftest intra-chain-nonce-reuse-across-different-links-is-rejected
  ;; two links of the SAME chain sharing an [iss nonce] — even with no
  ;; caller-supplied store, the fresh-per-call default still catches this
  ;; because it's the SAME store instance for every link within one call.
  (let [root (mint-link seed-a did-b [wildcard] {:nonce "same-nonce"})
        ;; re-issue from the SAME seed (root's own iss) so [iss nonce] collides
        leaf (mint-link seed-a did-c [ledger-main] {:nonce "same-nonce"})
        r (cacao/verify-chain [root leaf])]
    (is (false? (:chain/valid? r)))
    (is (some #(= :chain/nonce-replay (:problem %)) (:chain/problems r)))))

(deftest default-fresh-store-per-chain-call-does-not-crash-but-cannot-protect-across-calls
  ;; mirrors the single-verify fallback test: omitting :nonce-store still
  ;; functions (no exception), but each verify-chain call gets its own
  ;; throwaway store, so replaying the SAME chain across two SEPARATE calls
  ;; (no store threaded through) is NOT caught.
  (let [root (mint-link seed-a did-b [wildcard])
        leaf (mint-link seed-b did-c [ledger-main])
        chain [root leaf]]
    (is (true? (:chain/valid? (cacao/verify-chain chain))))
    (is (true? (:chain/valid? (cacao/verify-chain chain)))
        (str "replaying the SAME chain a second time with no store ALSO verifies true — "
             "proof the default fallback provides no cross-call replay protection"))))

(deftest premature-or-stale-presentation-does-not-burn-the-nonce
  ;; CONFIRMED BUG regression (independent review of this PR): nonce-problems
  ;; used to gate recording ONLY on signature validity (links' :valid?, which
  ;; never reflected temporal bounds since the per-link `verify` inside
  ;; verify-chain is called with no :now) -- so a validly-signed but
  ;; not-yet-valid or already-expired link still burned its nonce against
  ;; the real persistent store, permanently locking out the legitimate
  ;; holder from ever presenting that exact chain again once it actually
  ;; became valid. This proves a not-yet-valid presentation is correctly
  ;; rejected WITHOUT side-effecting the store, so the later, genuinely
  ;; valid presentation still succeeds.
  (let [store (cacao/fresh-nonce-store)
        root (mint-link seed-a did-b [wildcard])
        leaf (mint-link seed-b did-c [ledger-main])
        chain [root leaf]]
    (testing "presented before iat: rejected as not-yet-valid"
      (let [r (cacao/verify-chain chain {:now "2026-06-01T00:00:00Z" :nonce-store store})]
        (is (false? (:chain/valid? r)))
        (is (every? #(= :chain/not-yet-valid (:problem %)) (:chain/problems r)))))
    (testing "presented again later, now genuinely within the valid window: must succeed"
      (let [r (cacao/verify-chain chain {:now "2026-07-01T00:00:00Z" :nonce-store store})]
        (is (true? (:chain/valid? r))
            "the earlier not-yet-valid presentation must not have burned the nonce")))))

(deftest expired-presentation-also-does-not-burn-the-nonce
  (let [store (cacao/fresh-nonce-store)
        root (mint-link seed-a did-b [wildcard])
        leaf (mint-link seed-b did-c [ledger-main])
        chain [root leaf]]
    (testing "presented after exp: rejected as expired"
      (let [r (cacao/verify-chain chain {:now "2026-07-27T00:00:00Z" :nonce-store store})]
        (is (false? (:chain/valid? r)))
        (is (every? #(= :chain/expired (:problem %)) (:chain/problems r)))))
    (testing "presented again within the (already past) valid window: must still succeed --
              proves the expired presentation didn't burn the nonce either"
      (let [r (cacao/verify-chain chain {:now "2026-07-01T00:00:00Z" :nonce-store store})]
        (is (true? (:chain/valid? r)))))))

(deftest malformed-chain-input-never-throws
  (doseq [garbage [nil 42 "b64" {} [] [nil] [42] ["not-b64!!!"] ["" ""]]]
    (let [r (cacao/verify-chain garbage)]
      (is (false? (:chain/valid? r)) (pr-str garbage))
      (is (seq (:chain/problems r)) (pr-str garbage)))))

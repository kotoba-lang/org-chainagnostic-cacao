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

(deftest tamper-is-rejected
  (let [{:keys [cacao-b64]} (cacao/mint (opts-for (seed)))
        m (cacao/verify cacao-b64)]
    (is (true? (:valid? m)))
    ;; flip a byte in the signature → invalid
    (let [raw (.decode (Base64/getDecoder) cacao-b64)
          _ (aset-byte raw (dec (count raw)) (unchecked-byte (bit-xor (aget raw (dec (count raw))) 1)))
          tampered (.encodeToString (Base64/getEncoder) raw)]
      (is (false? (:valid? (cacao/verify tampered)))))))

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

(deftest malformed-chain-input-never-throws
  (doseq [garbage [nil 42 "b64" {} [] [nil] [42] ["not-b64!!!"] ["" ""]]]
    (let [r (cacao/verify-chain garbage)]
      (is (false? (:chain/valid? r)) (pr-str garbage))
      (is (seq (:chain/problems r)) (pr-str garbage)))))

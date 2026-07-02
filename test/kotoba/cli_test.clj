(ns kotoba.cli-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.cli :as cli]
            [ed25519.core :as ed]
            [cacao.core :as cacao])
  (:import (java.util Base64)
           (java.time Instant)))

;; ── pure arg handling (portable) ──────────────────────────────────────────────

(deftest parse-opts-basics
  (is (= {} (cli/parse-opts [])))
  (is (= {:seed "abc"} (cli/parse-opts ["--seed" "abc"])))
  (testing "repeated flags accumulate in order"
    (is (= {:resource ["r1" "r2" "r3"]}
           (cli/parse-opts ["--resource" "r1" "--resource" "r2" "--resource" "r3"]))))
  (testing "non-flag tokens are ignored"
    (is (= {:aud "did:key:zAUD"} (cli/parse-opts ["junk" "--aud" "did:key:zAUD"])))))

(deftest as-vec-normalizes
  (is (= [] (cli/as-vec nil)))
  (is (= ["x"] (cli/as-vec "x")))
  (is (= ["x" "y"] (cli/as-vec ["x" "y"]))))

(deftest validate-rules
  (is (= [] (cli/validate :seed {})))
  (is (seq (cli/validate :did {})) "did needs --seed")
  (is (= [] (cli/validate :did {:seed "s"})))
  (is (= 3 (count (cli/validate :cacao {}))) "cacao needs seed, aud, resource")
  (is (= [] (cli/validate :cacao {:seed "s" :aud "a" :resource "r"})))
  (is (seq (cli/validate :bogus {}))))

;; ── crypto (JVM) ──────────────────────────────────────────────────────────────

(def ^:private b64enc #(.encodeToString (Base64/getEncoder) %))

;; deterministic fixed seed (bytes 0..31) → base64
(def ^:private seed-bytes (byte-array (range 0 32)))
(def ^:private seed-b64 (b64enc seed-bytes))

(deftest seed->did-is-deterministic-and-matches-lib
  (let [d1 (cli/seed->did seed-b64)
        d2 (cli/seed->did seed-b64)]
    (is (= d1 d2) "same seed → same did every time")
    (is (= (ed/did-key-from-seed seed-bytes) d1) "matches ed25519.core derivation")
    (is (clojure.string/starts-with? d1 "did:key:z6Mk"))))

(deftest gen-seed-is-32-bytes-and-random
  (is (= 32 (count (cli/gen-seed))))
  (is (not= (seq (cli/gen-seed)) (seq (cli/gen-seed))) "two seeds differ"))

(deftest cacao-mint-verify-roundtrip
  (let [now (Instant/parse "2026-07-02T00:00:00Z")
        opts {:seed seed-b64 :aud "did:key:zAUD"
              :resource ["kotoba://can/kotobase:pin" "kotoba://graph/g"]
              :ttl-h "48" :nonce "n1"}
        {:keys [cacao-b64 iss iat exp resources]} (cli/mint-cacao opts now)
        v (cacao/verify cacao-b64)]
    (is (= (ed/did-key-from-seed seed-bytes) iss) "iss derived from seed")
    (is (true? (:valid? v)))
    (is (= iss (:iss v)))
    (is (= "2026-07-02T00:00:00Z" iat))
    (is (= "2026-07-04T00:00:00Z" exp) "iat + ttl-h(48) = exp")
    (is (= ["kotoba://can/kotobase:pin" "kotoba://graph/g"] resources))
    (is (= resources (:resources (:payload v))))))

(deftest cacao-default-ttl-and-random-nonce
  (let [now (Instant/parse "2026-07-02T00:00:00Z")
        {:keys [exp]} (cli/mint-cacao {:seed seed-b64 :aud "did:key:zAUD"
                                       :resource "kotoba://x"} now)]
    (is (= "2026-07-03T00:00:00Z" exp) "default ttl is 24h")))

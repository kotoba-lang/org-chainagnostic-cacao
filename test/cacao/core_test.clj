(ns cacao.core-test
  (:require [clojure.test :refer [deftest is]]
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

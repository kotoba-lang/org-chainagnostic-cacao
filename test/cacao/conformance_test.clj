(ns cacao.conformance-test
  "The suite must itself be right: a case that differs in more than one way
  proves nothing, and a runner that scores a measurement as a failure would
  make the report unreadable."
  (:require [clojure.test :refer [deftest is testing]]
            [cacao.core :as cacao]
            [cacao.conformance :as conf]))

(def ^:private seed (byte-array (repeat 32 (byte 11))))
(def ^:private opts {:seed seed
                     :now-iso "2026-07-27T10:15:30Z"
                     :exp-iso "2026-07-27T10:20:30Z"})

(deftest every-case-mints-something-sendable
  (let [cs (conf/cases opts)]
    (is (= 11 (count cs)))
    (is (every? #(string? (:case/cacao %)) cs))
    (is (= (count cs) (count (distinct (map :case/id cs)))))))

(deftest each-rejection-case-differs-in-exactly-one-way
  (testing "bundling two deviations would make a rejection uninformative"
    (let [by-id (into {} (map (juxt :case/id identity) (conf/cases opts)))
          payload-of (fn [id] (cacao/decode-payload (:case/cacao (by-id id))))]
      (is (thrown? Exception (payload-of :nope)) "sanity: unknown id has no case")
      (testing "missing-pin keeps a valid graph scope"
        (let [rs (:resources (payload-of :missing-pin-capability))]
          (is (not (some #{cacao/kotobase-pin-capability} rs)))
          (is (some #(clojure.string/starts-with? % "kotoba://graph/") rs))))
      (testing "cid-scope keeps the pin capability"
        (let [rs (:resources (payload-of :graph-scope-is-a-cid))]
          (is (some #{cacao/kotobase-pin-capability} rs))
          (is (some #(clojure.string/starts-with? % "kotoba://graph/bafy") rs))))
      (testing "the timestamp cases keep both required resources"
        (doseq [id [:iat-with-fractional-seconds :iat-as-epoch-seconds]]
          (let [rs (:resources (payload-of id))]
            (is (some #{cacao/kotobase-pin-capability} rs))
            (is (some #(clojure.string/starts-with? % "kotoba://graph/did:key:") rs))))))))

(deftest the-vocabulary-cases-are-mirror-images
  (testing "together they report WHICH backend is answering -- nothing else
            observable distinguishes that"
    (let [by-id (into {} (map (juxt :case/id identity) (conf/cases opts)))
          caps (fn [id] (->> (:resources (cacao/decode-payload (:case/cacao (by-id id))))
                             (filter #(clojure.string/starts-with? % "kotoba://can/"))
                             set))]
      (is (contains? (caps :xrpc-vocabulary-only) "kotoba://can/datom:read"))
      (is (not (contains? (caps :xrpc-vocabulary-only) "kotoba://can/graph:query")))
      (is (contains? (caps :d1-vocabulary-only) "kotoba://can/graph:query"))
      (is (not (contains? (caps :d1-vocabulary-only) "kotoba://can/datom:read")))
      (is (every? (caps :both-vocabularies)
                  ["kotoba://can/datom:read" "kotoba://can/graph:query"])))))

(deftest the-tampered-case-really-is-tampered
  (let [by-id (into {} (map (juxt :case/id identity) (conf/cases opts)))
        good (:case/cacao (by-id :valid))
        bad (:case/cacao (by-id :tampered-signature))]
    (is (not= good bad))
    (is (false? (:valid? (cacao/verify bad))))))

(deftest a-measurement-is-never-scored-as-a-failure
  (testing ":unknown cases report what a deployment does; treating them as
            failures would make the report unreadable during a migration"
    (let [{:keys [summary results]} (conf/run (constantly {:status 401 :body "{}"}) opts)]
      (is (= 3 (:measured summary)) "eip4361, xrpc-only, d1-only")
      (is (every? #(= :measured (:result/agrees? %))
                  (filter #(= :unknown (:case/expect %)) results))))))

(deftest a-deployment-that-accepts-everything-is-reported-as-disagreeing
  (testing "the state the apex was in until 2026-07-27: not verifying at all"
    (let [{:keys [summary]} (conf/run (constantly {:status 200 :body "{\"ok\":true}"}) opts)]
      (is (pos? (:disagree summary))
          "every reject-case should disagree when nothing is enforced"))))

(deftest a-deployment-that-rejects-everything-fails-the-valid-cases
  (let [{:keys [summary]} (conf/run (constantly {:status 401 :body "{}"}) opts)]
    (is (pos? (:disagree summary)))))

(deftest an-unreachable-target-is-not-a-rejection
  (testing "a probe that could not connect must not read as 'the rule is
            enforced' -- that is how an outage gets recorded as compliance"
    (let [{:keys [results]} (conf/run (constantly {:status nil :body ""}) opts)]
      (is (every? #(= :unreachable (:result/outcome %)) results)))))

(deftest the-absence-of-a-reason-is-itself-reported
  (testing "the edge computes a precise message and drops it; measuring that
            gap is what makes it fixable"
    (let [none (conf/run (constantly {:status 401 :body "{\"ok\":false,\"error\":\"Unauthorized\"}"}) opts)
          some* (conf/run (constantly {:status 401 :body "{\"error\":\"Unauthorized\",\"reason\":\"cacao/iat-format\"}"}) opts)]
      (is (false? (:reason-visible? (:summary none))))
      (is (true? (:reason-visible? (:summary some*))))
      (is (clojure.string/includes? (conf/report none) "carry NO reason")))))

(deftest the-vocabulary-table-is-the-one-source
  (testing "the outage was two names for one permission and no table"
    (is (= #{"datom:read" "graph:query"} (set (conf/read-capabilities))))
    (is (contains? (set (conf/write-capabilities)) "datom:transact"))))

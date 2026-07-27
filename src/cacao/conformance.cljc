(ns cacao.conformance
  "An executable contract for what a kotobase deployment accepts.

  ## Why this exists

  Every CACAO rejection the kotobase apex produces looks the same from the
  outside: `{\"ok\":false,\"error\":\"Unauthorized\"}`. The edge computes a
  precise reason — `invalid CACAO iat`, `CACAO graph scope does not include
  issuer DID`, `CACAO nonce replay` — and then discards it
  (`proxy/resolve-viewer`'s `(.catch (fn [_] nil))`). So a client that drifts
  from the contract learns about it in production, as an outage, with one bit
  of information.

  On 2026-07-27 that cost a full day across four separate failures with
  identical symptoms:

    - `kagi push` had been dead for months because `(str (Instant/now))`
      renders nanoseconds and the apex's `parse-utc-seconds` accepts only
      `YYYY-MM-DDTHH:MM:SSZ`;
    - the edge began verifying CACAOs it had previously trusted, so every
      client minting the old shape broke at once;
    - `datomic.*` began bridging to kotobase-storage-d1, which names the same
      permissions differently (`graph:query` vs `datom:read`), and every
      marketplace read 401'd;
    - refs moved from content-addressed CIDs to literal
      `kotobase/db/<did>/<name>` strings, so existing data became invisible
      (`UnknownGraphCid`) rather than missing.

  Not one of those is exotic. Each is a contract this namespace can state and
  a probe can check in seconds.

  ## What this is

  A set of NAMED CASES. Each case mints a CACAO that differs from a valid one
  in exactly one way and says what should happen. `run` takes a `probe` — a
  function that sends one CACAO at a target and reports what came back — so
  the same suite runs against a live deployment, a local worker, or a stub.

  It reports what a deployment ACTUALLY enforces, which is a different
  question from what its source says it enforces. Point it at a target before
  and after a migration and the diff is the answer.

  ## What this deliberately does NOT do

  It does not assert that a rejection carries a reason, because today none of
  them do. `reason-visible?` in the report is the measurement of that gap —
  when the edge starts returning reason codes, this suite is where that
  becomes checkable."
  (:require [clojure.string :as str]
            [cacao.core :as cacao]))

;; ── the vocabulary, in one place ─────────────────────────────────────────────
;;
;; The XRPC edge and kotobase-storage-d1 name the same permissions
;; differently, and nothing mapped between them. A client that carried only
;; one vocabulary worked until the day the other side started answering.

(def capability-vocabularies
  "The same permission, under each backend's own name.

  Carrying BOTH is what a client should do while more than one backend can
  answer: extra capabilities ride along harmlessly on the side that does not
  check them, and guessing which side will answer is how an outage happens."
  {:read    {:xrpc "datom:read"     :d1 "graph:query"}
   :write   {:xrpc "datom:transact" :d1 "datom:transact"}
   :tx      {:xrpc "tx:create"      :d1 nil}})

(defn capabilities-for
  "Every name a given permission goes by, deduplicated."
  [permission]
  (->> (get capability-vocabularies permission) vals (remove nil?) distinct vec))

(defn read-capabilities [] (capabilities-for :read))
(defn write-capabilities []
  (vec (distinct (concat (capabilities-for :write) (capabilities-for :tx)))))

;; ── cases ────────────────────────────────────────────────────────────────────

(def ^:private base-iat "2026-07-27T10:15:30Z")

(defn- valid-spec [seed nonce now-iso exp-iso]
  {:seed seed :nonce nonce :iat now-iso :exp exp-iso
   :op-caps (read-capabilities)})

(defn cases
  "Every case, as data. `seed` signs them; `now-iso`/`exp-iso` come from the
  caller so a run is reproducible.

  Each case is one deviation from a valid CACAO. Bundling two deviations into
  one case would make a rejection uninformative — the whole point is that a
  failure names which rule it broke."
  [{:keys [seed now-iso exp-iso]}]
  (let [iss (cacao/mint-kotobase-apex (valid-spec seed "probe-valid" now-iso exp-iso))
        did (:iss iss)]
    [{:case/id :valid
      :case/expect :accept
      :case/why "a correctly shaped apex CACAO"
      :case/cacao (:cacao-b64 iss)}

     {:case/id :missing-pin-capability
      :case/expect :reject
      :case/reason "CACAO missing kotobase:pin capability"
      :case/why "the apex requires kotoba://can/kotobase:pin explicitly"
      :case/cacao (:cacao-b64
                   (cacao/mint {:seed seed :aud cacao/kotobase-apex-aud
                                :domain cacao/kotobase-apex-domain
                                :iat now-iso :exp exp-iso :nonce "probe-nopin"
                                :header-type "caip122"
                                :resources [(str "kotoba://graph/" did)]}))}

     {:case/id :graph-scope-is-a-cid
      :case/expect :reject
      :case/reason "CACAO graph scope does not include issuer DID"
      :case/why "the scope must be the ISSUER DID; a graph CID is refused even
                 though the request body names that same CID"
      :case/cacao (:cacao-b64
                   (cacao/mint {:seed seed :aud cacao/kotobase-apex-aud
                                :domain cacao/kotobase-apex-domain
                                :iat now-iso :exp exp-iso :nonce "probe-cidscope"
                                :header-type "caip122"
                                :resources [cacao/kotobase-pin-capability
                                            "kotoba://graph/bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}))}

     {:case/id :iat-with-fractional-seconds
      :case/expect :reject
      :case/reason "invalid CACAO iat"
      :case/why "THE failure that hid for months. (str (Instant/now)) renders
                 nanoseconds when they are non-zero, so most mints were
                 rejected and the ones landing on a whole second passed —
                 an intermittent auth failure reads as a flaky network"
      :case/cacao (:cacao-b64
                   (cacao/mint {:seed seed :aud cacao/kotobase-apex-aud
                                :domain cacao/kotobase-apex-domain
                                :iat "2026-07-27T10:15:30.123456789Z" :exp exp-iso
                                :nonce "probe-fracsec" :header-type "caip122"
                                :resources (cacao/kotobase-apex-resources did)}))}

     {:case/id :iat-as-epoch-seconds
      :case/expect :reject
      :case/reason "invalid CACAO iat"
      :case/why "epoch seconds are the other obvious encoding and are also
                 refused; parse-utc-seconds matches one regex and nothing else"
      :case/cacao (:cacao-b64
                   (cacao/mint {:seed seed :aud cacao/kotobase-apex-aud
                                :domain cacao/kotobase-apex-domain
                                :iat "1785140130" :exp exp-iso
                                :nonce "probe-epoch" :header-type "caip122"
                                :resources (cacao/kotobase-apex-resources did)}))}

     {:case/id :expired
      :case/expect :reject
      :case/reason "expired CACAO"
      :case/why "temporal window enforcement"
      :case/cacao (:cacao-b64
                   (cacao/mint-kotobase-apex
                    {:seed seed :nonce "probe-expired"
                     :iat "2020-01-01T00:00:00Z" :exp "2020-01-01T00:05:00Z"
                     :op-caps (read-capabilities)}))}

     {:case/id :eip4361-header
      :case/expect :unknown
      :case/why "the apex's own docs and one drifted copy disagreed about
                 whether `h` matters; this measures it rather than asserting it"
      :case/cacao (:cacao-b64
                   (cacao/mint {:seed seed :aud cacao/kotobase-apex-aud
                                :domain cacao/kotobase-apex-domain
                                :iat now-iso :exp exp-iso :nonce "probe-eip"
                                :header-type "eip4361"
                                :resources (cacao/kotobase-apex-resources did)}))}

     {:case/id :xrpc-vocabulary-only
      :case/expect :unknown
      :case/why "carries datom:read but NOT graph:query. Accepted while the
                 XRPC edge answers; refused the moment datomic.* bridges to
                 kotobase-storage-d1. This single case is the whole of the
                 2026-07-27 marketplace outage"
      :case/cacao (:cacao-b64
                   (cacao/mint-kotobase-apex
                    {:seed seed :nonce "probe-xrpconly" :iat now-iso :exp exp-iso
                     :op-caps ["datom:read"]}))}

     {:case/id :d1-vocabulary-only
      :case/expect :unknown
      :case/why "the mirror image: graph:query but not datom:read. Together
                 with the previous case this reports WHICH backend is
                 answering, which no other observation makes visible"
      :case/cacao (:cacao-b64
                   (cacao/mint-kotobase-apex
                    {:seed seed :nonce "probe-d1only" :iat now-iso :exp exp-iso
                     :op-caps ["graph:query"]}))}

     {:case/id :both-vocabularies
      :case/expect :accept
      :case/why "what a client should send while more than one backend can
                 answer"
      :case/cacao (:cacao-b64
                   (cacao/mint-kotobase-apex
                    {:seed seed :nonce "probe-both" :iat now-iso :exp exp-iso
                     :op-caps (read-capabilities)}))}

     {:case/id :tampered-signature
      :case/expect :reject
      :case/reason "signature"
      :case/why "a deployment that accepts this is not verifying at all —
                 which was true of the apex until 2026-07-27, and is exactly
                 the cross-tenant hole its own docstring now describes"
      :case/cacao (let [{:keys [cacao-b64]} (cacao/mint-kotobase-apex
                                             (valid-spec seed "probe-tamper" now-iso exp-iso))]
                    ;; flip one character of the base64 envelope
                    (str (subs cacao-b64 0 (- (count cacao-b64) 2))
                         (if (= \A (nth cacao-b64 (- (count cacao-b64) 2))) "B" "A")
                         (subs cacao-b64 (dec (count cacao-b64)))))}]))

;; ── running ──────────────────────────────────────────────────────────────────

(defn- classify
  "What a probe result means, without knowing the target's error vocabulary."
  [{:keys [status body]}]
  (cond
    (and status (<= 200 status 299)) :accept
    (and status (#{401 403} status)) :reject
    (and status (= 410 status))      :gone
    (nil? status)                    :unreachable
    :else                            :other))

(defn- reason-of
  "A reason from the response body, when the target bothers to give one.

  Today none do — the edge computes a precise message and drops it. This
  reads whichever field a future deployment might use rather than assuming
  one, because measuring the absence is the point."
  [{:keys [body]}]
  (let [b (str body)]
    (some (fn [k] (when-let [m (re-find (re-pattern (str "\"" k "\"\\s*:\\s*\"([^\"]+)\"")) b)]
                    (second m)))
          ["reason" "detail" "details" "cacao_error" "error_reason"])))

(defn run
  "Run every case against `probe`.

  `probe` is `(fn [cacao-b64] -> {:status int :body string})`. Keeping the
  transport out of this namespace is what lets the same suite run against
  kotobase.net, a `wrangler dev` worker, or a stub in a unit test.

  Returns `{:results [...] :summary {...}}`. A case whose `:case/expect` is
  `:unknown` is never a failure — it is a MEASUREMENT, and the report is
  where you read which backend is answering."
  [probe opts]
  (let [cs (cases opts)
        results (mapv (fn [c]
                        (let [r (probe (:case/cacao c))
                              got (classify r)]
                          (-> c
                              (dissoc :case/cacao)
                              (assoc :result/outcome got
                                     :result/status (:status r)
                                     :result/reason (reason-of r)
                                     :result/agrees?
                                     (case (:case/expect c)
                                       :unknown :measured
                                       (= got (:case/expect c)))))))
                      cs)
        checked (remove #(= :measured (:result/agrees? %)) results)]
    {:results results
     :summary {:total (count results)
               :checked (count checked)
               :agree (count (filter :result/agrees? checked))
               :disagree (count (remove :result/agrees? checked))
               :measured (- (count results) (count checked))
               ;; The gap this suite exists to make visible.
               :reason-visible? (boolean (some :result/reason results))}}))

(defn report
  "The run, as lines a human reads in a terminal."
  [{:keys [results summary]}]
  (str/join
   "\n"
   (concat
    (for [r results]
      (format "%-28s %-9s %-8s %s"
              (name (:case/id r))
              (name (or (:result/outcome r) :?))
              (case (:result/agrees? r)
                :measured "measured"
                true      "ok"
                "DISAGREE")
              (or (:result/reason r) "")))
    [""
     (format "%d checked, %d agree, %d disagree, %d measured"
             (:checked summary) (:agree summary)
             (:disagree summary) (:measured summary))
     (if (:reason-visible? summary)
       "rejections carry a reason"
       "rejections carry NO reason — every cause looks identical from outside")])))

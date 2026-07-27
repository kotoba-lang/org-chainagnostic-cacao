;; Run the conformance suite against a live kotobase deployment.
;;   clojure -M:local -i scripts/probe_live.clj -e '(probe! "https://kotobase.net")'
(require '[cacao.conformance :as conf] '[cacao.core :as cacao])
(import '[java.net URI]
        '[java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
        '[java.time Instant]
        '[java.time.temporal ChronoUnit]
        '[java.security SecureRandom])

(defn- send-one [base cacao-b64 did]
  (try
    (let [;; hand-built JSON: this script must run with no deps beyond the
          ;; library itself, so it can be pointed at a deployment from a clean
          ;; clone during an incident.
          body (str "{\"graph\":\"kotobase/db/" did "/conformance-probe\","
                    "\"query_edn\":\"[nil \\\":probe/nothing\\\" nil]\","
                    "\"cacao_b64\":\"" cacao-b64 "\"}")
          req (-> (HttpRequest/newBuilder (URI/create (str base "/xrpc/ai.gftd.apps.kotobase.datomic.q")))
                  (.header "content-type" "application/json")
                  (.header "authorization" (str "CACAO " cacao-b64))
                  (.header "x-kotoba-did" did)
                  (.method "POST" (HttpRequest$BodyPublishers/ofString body))
                  (.build))
          resp (.send (HttpClient/newHttpClient) req (HttpResponse$BodyHandlers/ofString))]
      {:status (.statusCode resp) :body (.body resp)})
    (catch Exception e {:status nil :body (str (.getMessage e))})))

(defn probe! [base]
  (let [seed (byte-array 32)
        _ (.nextBytes (SecureRandom.) seed)
        did (:iss (cacao/mint-kotobase-apex {:seed seed :nonce "id-probe"
                                             :iat "2026-07-27T10:15:30Z"
                                             :exp "2026-07-27T10:20:30Z"}))
        now (.truncatedTo (Instant/now) ChronoUnit/SECONDS)
        opts {:seed seed :now-iso (str now) :exp-iso (str (.plusSeconds now 300))}]
    (println (str "target: " base "\nissuer: " did "\n"))
    (println (conf/report (conf/run #(send-one base % did) opts)))))

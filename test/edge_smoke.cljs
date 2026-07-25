;; nbb (ClojureScript-on-Node) smoke for the edge mint/verify pair — the
;; WebCrypto half of this repo, which the JVM test suite (clojure -M:test)
;; cannot reach at all: cacao.edge.* is CLJS-only by construction
;; (js/crypto.subtle, js/Uint8Array, js/btoa).
;;
;;   nbb --classpath src:test test/edge_smoke.cljs
;;
;; Requires a Node with Ed25519 in WebCrypto (Node >= 20). Exits nonzero on
;; any failure. Mints with cacao.edge.mint and verifies with
;; cacao.edge.verify, so a break in either side's SIWE reconstruction or CBOR
;; key order fails here rather than in a product Worker.
(require '[cacao.edge.mint :as mint]
         '[cacao.edge.verify :as verify])

(def domain "authn.kotobase.net")
(def aud "https://kotobase.net")
(def resources ["kotoba://can/kotobase:pin"])

(def failures (atom []))

(defn check! [label ok?]
  (if ok?
    (js/console.log "ok  -" label)
    (do (js/console.error "FAIL-" label)
        (swap! failures conj label))))

(defn iso [epoch-sec]
  (str (.replace (.toISOString (js/Date. (* 1000 epoch-sec))) #"\.\d{3}Z$" "Z")))

(defn keypair []
  (.generateKey js/crypto.subtle #js {:name "Ed25519"} true #js ["sign" "verify"]))

(defn signer [private-key]
  (fn [msg-bytes] (.sign js/crypto.subtle "Ed25519" private-key msg-bytes)))

(defn mint-at [kp did {:keys [iat exp resources nonce aud]}]
  (mint/mint did (signer (.-privateKey kp))
             {:domain domain
              :aud (or aud "https://kotobase.net")
              :nonce (or nonce "n1")
              :iat (iso iat)
              :exp (when exp (iso exp))
              :resources resources}))

(def now 1800000000)

(-> (keypair)
    (.then (fn [kp]
             (-> (.exportKey js/crypto.subtle "raw" (.-publicKey kp))
                 (.then (fn [raw]
                          (let [did (mint/did-key-from-raw-ed25519-pub (js/Uint8Array. raw))]
                            (check! "did:key is Ed25519 multibase"
                                    (and (string? did) (.startsWith did "did:key:z6Mk")))
                            (-> (mint-at kp did {:iat now :exp (+ now 3600) :resources resources})
                                (.then (fn [{:keys [cacao-b64 iss]}]
                                         (check! "mint returns its own iss" (= iss did))
                                         (js/Promise.all
                                          #js [(verify/verify cacao-b64 (+ now 60))
                                               (verify/verify cacao-b64 (+ now 7200))
                                               (verify/verify (str (subs cacao-b64 0 (- (count cacao-b64) 8))
                                                                   "AAAAAAA=")
                                                              (+ now 60))
                                               (mint-at kp did {:iat now :exp (+ now 3600)
                                                                :resources resources :nonce "n2"})])))
                                (.then (fn [[fresh expired tampered other]]
                                         (check! "fresh CACAO verifies" (true? (aget fresh "valid")))
                                         (check! "verified iss is the minting did"
                                                 (= did (aget fresh "iss")))
                                         (check! "resources round-trip through CBOR"
                                                 (= (vec resources)
                                                    (vec (array-seq (aget (aget fresh "payload") "resources")))))
                                         (check! "aud round-trips" (= aud (aget (aget fresh "payload") "aud")))
                                         (check! "expired CACAO is rejected"
                                                 (and (false? (aget expired "valid"))
                                                      (= "expired CACAO" (aget expired "error"))))
                                         (check! "tampered blob is rejected"
                                                 (false? (aget tampered "valid")))
                                         (-> (verify/verify (:cacao-b64 other) (+ now 60))
                                             (.then (fn [r]
                                                      (check! "a second mint from the same key also verifies"
                                                              (true? (aget r "valid")))))))))))))))
    (.then (fn [_]
             (if (seq @failures)
               (do (js/console.error "FAILED:" (count @failures))
                   (set! (.-exitCode js/process) 1))
               (js/console.log "\nedge mint/verify smoke: all checks passed"))))
    (.catch (fn [error]
              (js/console.error "threw:" error)
              (set! (.-exitCode js/process) 1))))

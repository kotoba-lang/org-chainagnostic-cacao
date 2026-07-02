;; kotoba.cli — identity-primitives CLI (DID / CACAO / seed).
;;
;; A tiny, self-sovereign command surface over the kotoba identity stack:
;;
;;   kotoba seed                         → mint a fresh raw Ed25519 seed (base64). SECRET.
;;   kotoba did    --seed <b64>          → derive the public did:key:z6Mk… from a seed.
;;   kotoba cacao  --seed <b64> --aud <did> --resource <uri> [--ttl-h N] [--nonce X]
;;                                       → mint a signed, expiring CACAO capability (base64).
;;
;; DESIGN: pure argument handling (parse / validate / usage) is portable .cljc so
;; it reads & tests the same on any Clojure host. All CRYPTO + IO is JVM-only and
;; lives behind #?(:clj …): seed randomness (SecureRandom), base64 (java.util.Base64),
;; the iat/exp instants (java.time), and the actual require of ed25519.core /
;; cacao.core (both JVM libraries). Runs on babashka — bb has JCA Ed25519 sign/verify,
;; and ed25519.core derives the public key in pure Clojure, so nothing here needs a
;; native crypto dep. We DERIVE the issuer DID from the seed and NEVER print the seed
;; except from the `seed` command (whose whole job is to emit it, with a stderr warning).
(ns kotoba.cli
  (:require [clojure.string :as str]
            #?@(:clj [[ed25519.core :as ed]
                      [cacao.core :as cacao]]))
  #?(:clj (:import (java.security SecureRandom)
                   (java.util Base64)
                   (java.time Instant)
                   (java.time.temporal ChronoUnit))))

;; ── pure argument handling (portable .cljc) ───────────────────────────────────

(def usage
  (str "kotoba — DID / CACAO / seed identity primitives\n"
       "\n"
       "USAGE\n"
       "  kotoba seed\n"
       "  kotoba did   --seed <b64>\n"
       "  kotoba cacao --seed <b64> --aud <did> --resource <uri> [--resource <uri> …]\n"
       "               [--ttl-h <hours>] [--nonce <str>]\n"
       "\n"
       "COMMANDS\n"
       "  seed   Generate a new 32-byte Ed25519 seed, base64. THIS IS SECRET — keep it safe.\n"
       "  did    Derive the public did:key:z6Mk… from a seed. Safe to publish.\n"
       "  cacao  Mint a signed, expiring CACAO capability (iss is derived from the seed).\n"
       "\n"
       "OPTIONS\n"
       "  --seed <b64>    raw 32-byte Ed25519 seed, base64-encoded (SECRET)\n"
       "  --aud <did>     audience DID the CACAO is minted for\n"
       "  --resource <u>  a kotoba:// resource URI to grant; repeatable\n"
       "  --ttl-h <n>     lifetime in hours from now (default 24)\n"
       "  --nonce <s>     explicit nonce (default: random)\n"))

(defn parse-opts
  "Parse a flat `--flag value` argv (a seq of strings) into a keyword→value map.
   A flag repeated more than once accumulates into a vector (in argv order).
   Purely functional — no IO, no host interop."
  [args]
  (loop [m {} args (seq args)]
    (if-let [a (first args)]
      (if (str/starts-with? a "--")
        (let [k (keyword (subs a 2))
              v (second args)
              m (if (contains? m k)
                  (update m k (fn [old] (conj (if (vector? old) old [old]) v)))
                  (assoc m k v))]
          (recur m (nnext args)))
        (recur m (next args)))
      m)))

(defn as-vec
  "Normalize a parse-opts value (nil | scalar | vector) into a vector."
  [v]
  (cond (nil? v) [] (vector? v) v :else [v]))

(defn validate
  "Given a command keyword and parsed opts, return a seq of human-readable error
   strings (empty when the invocation is well-formed). Pure."
  [command opts]
  (case command
    :seed  []
    :did   (if (:seed opts) [] ["--seed <b64> is required"])
    :cacao (cond-> []
             (not (:seed opts)) (conj "--seed <b64> is required")
             (not (:aud opts))  (conj "--aud <did> is required")
             (empty? (as-vec (:resource opts))) (conj "at least one --resource <uri> is required"))
    [(str "unknown command: " (name (or command :?)))]))

;; ── JVM-only crypto + IO (behind #?(:clj …)) ──────────────────────────────────

#?(:clj
   (do
     (defn ^:private b64-encode ^String [^bytes b]
       (.encodeToString (Base64/getEncoder) b))

     (defn ^:private b64-decode ^bytes [^String s]
       (.decode (Base64/getDecoder) (str/trim s)))

     (defn gen-seed
       "32 cryptographically-random bytes — a raw Ed25519 seed. SECRET output."
       ^bytes []
       (let [b (byte-array 32)]
         (.nextBytes (SecureRandom.) b)
         b))

     (defn ^:private now-instant ^Instant [] (.truncatedTo (Instant/now) ChronoUnit/SECONDS))

     (defn ^:private random-nonce ^String []
       (let [b (byte-array 8)] (.nextBytes (SecureRandom.) b) (ed/hexify b)))

     (defn seed->did
       "base64 seed → did:key:z6Mk… (public). Deterministic."
       ^String [^String seed-b64]
       (ed/did-key-from-seed (b64-decode seed-b64)))

     (defn mint-cacao
       "Mint a CACAO from parsed opts. Returns cacao.core/mint's map plus the
        computed :iat/:exp. `now` is injectable for testing."
       ([opts] (mint-cacao opts (now-instant)))
       ([{:keys [seed aud resource ttl-h nonce]} ^Instant now]
        (let [ttl  (long (if ttl-h (Long/parseLong (str ttl-h)) 24))
              iat  (str now)
              exp  (str (.plus now ttl ChronoUnit/HOURS))
              res  (as-vec resource)
              minted (cacao/mint {:seed (b64-decode seed)
                                  :aud aud
                                  :iat iat :exp exp
                                  :nonce (or nonce (random-nonce))
                                  :resources res})]
          (assoc minted :iat iat :exp exp :resources res))))

     (defn ^:private eprintln [& xs] (binding [*out* *err*] (apply println xs)))

     (defn run
       "Dispatch one invocation. Prints results to stdout, human notes to stderr.
        Returns the process exit code (0 ok, 2 usage error). No System/exit here."
       [argv]
       (let [[cmd & rest] argv
             command (some-> cmd keyword)
             opts    (parse-opts rest)]
         (if (or (nil? cmd) (#{"help" "--help" "-h"} cmd))
           (do (eprintln usage) (if (nil? cmd) 2 0))
           (let [errs (validate command opts)]
             (if (seq errs)
               (do (doseq [e errs] (eprintln (str "error: " e)))
                   (eprintln "") (eprintln usage) 2)
               (case command
                 :seed  (let [s (gen-seed)]
                          (eprintln "# SECRET Ed25519 seed — store it safely; anyone with it IS you.")
                          (eprintln "# Its public did:key: " (ed/did-key-from-seed s))
                          (println (b64-encode s))
                          0)
                 :did   (do (println (seed->did (:seed opts))) 0)
                 :cacao (let [{:keys [cacao-b64 iss exp resources]} (mint-cacao opts)]
                          (eprintln (str "# minted CACAO — iss " iss))
                          (eprintln (str "#   aud=" (:aud opts) " exp=" exp
                                         " resources=" (pr-str resources)))
                          (println cacao-b64)
                          0)))))))

     (defn -main [& args]
       (System/exit (run (vec args))))))

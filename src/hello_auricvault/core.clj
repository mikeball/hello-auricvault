(ns hello-auricvault.core
  (:require [clj-http.client :as client]
            [cheshire.core :refer :all]
            [pandect.algo.sha512 :refer [sha512-hmac]]
            [environ.core :refer [env]]))

(defn get-timestamp []
  (str (quot (System/currentTimeMillis) 1000)))

(defn build-request [method id timestamp params]
  (generate-string
   {"id" id
    "method" method
    "params" [(merge {"mtid" (env :mtid)
                      "configurationId" (env :configuration-id)
                      "utcTimestamp" timestamp}
                     params)]}))

(defn build-tokenize-request [id timestamp cleartext]
  (build-request "encrypt" 1 timestamp {"retention" "forever"
                                        "segment" "543"
                                        "last4" ""
                                        "plaintextValue" cleartext}))

(defn build-detokenize-request [id timestamp token]
  (build-request "decrypt" 1 timestamp {"token" token}))


(defn make-request [body]
  (client/post (env :vault-url) 
               {:content-type :json
                :headers {"X-VAULT-HMAC" (sha512-hmac body (env :secret-key))}
                :body body}))


(defn tokenize [id cleartext]
  (-> (build-tokenize-request id (get-timestamp) cleartext)
      (make-request)))

(defn detokenize [token]
  (-> (build-detokenize-request 1 (get-timestamp) token)
      (make-request)))


(comment
  ;test tokens: ItPhRhl9ct0Xwca1111, 3YNkhT8QZr04c4A1112

  (let [result (tokenize 1 "4111111111111112")]
    (println result))
  
  (let [result (detokenize "ItPhRhl9ct0Xwca1112")]
    (println result))

)



  


(ns user-protocols.protocols
    (:require [http.api :as http]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn check-email-address
  ; @description
  ; For further information about this function, check the 'README.md' file.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:email-address-registered-f (function)
  ;  :email-address-valid-f (function)
  ;  :email-address-verified-f (function)
  ;  :optional-check-f (function)(opt)
  ;  :too-many-attempts-by-email-address-f (function)
  ;  :too-many-attempts-by-ip-address-f (function)}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address,
  ;   :invalid-request/missing-user-agent,
  ;   :illegal-client-behaviour/invalid-email-address-received,
  ;   :too-many-requests/too-many-attempts-by-email-address,
  ;   :too-many-requests/too-many-attempts-ip-address,
  ;   :standard-activity/unregistered-email-address-received,
  ;   :standard-activity/unverified-email-address-received,
  ;   :standard-activity/verified-email-address-received,
  ;   :unknown-error/optional-check-stage-failed
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [email-address-registered-f
                   email-address-valid-f
                   email-address-verified-f
                   optional-check-f
                   too-many-attempts-by-email-address-f
                   too-many-attempts-by-ip-address-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                   {:body :invalid-request/ip-address-missing                      :status 400}
             (not     (string? user-agent))                   {:body :invalid-request/user-agent-missing                      :status 400}
             (not     (email-address-valid-f))                {:body :illegal-client-behaviour/invalid-email-address-received :status 403}
             (boolean (too-many-attempts-by-email-address-f)) {:body :too-many-requests/too-many-attempts-by-email-address    :status 429}
             (boolean (too-many-attempts-by-ip-address-f))    {:body :too-many-requests/too-many-attempts-by-ip-address       :status 429}
             (and optional-check-f (not (optional-check-f)))  {:body :unknown-error/optional-check-stage-failed               :status 520}
             (not     (email-address-registered-f))           {:body :standard-activity/unregistered-email-address-received   :status 200}
             (not     (email-address-verified-f))             {:body :standard-activity/unverified-email-address-received     :status 200}
             :verified-email-address-received                 {:body :standard-activity/verified-email-address-received       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn check-phone-number
  ; @description
  ; For further information about this function, check the 'README.md' file.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:optional-check-f (function)(opt)
  ;  :phone-number-registered-f (function)
  ;  :phone-number-valid-f (function)
  ;  :phone-number-verified-f (function)
  ;  :too-many-attempts-by-phone-number-f (function)
  ;  :too-many-attempts-by-ip-address-f (function)}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address,
  ;   :invalid-request/missing-user-agent,
  ;   :illegal-client-behaviour/invalid-phone-number-received,
  ;   :too-many-requests/too-many-attempts-by-phone-number,
  ;   :too-many-requests/too-many-attempts-ip-address,
  ;   :standard-activity/unregistered-phone-number-received,
  ;   :standard-activity/unverified-phone-number-received,
  ;   :standard-activity/verified-phone-number-received,
  ;   :unknown-error/optional-check-stage-failed
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [optional-check-f
                   phone-number-registered-f
                   phone-number-valid-f
                   phone-number-verified-f
                   too-much-attempts-by-ip-address-f
                   too-much-attempts-by-phone-number-f
                   user-logged-in-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                  {:body :invalid-request/ip-address-missing                     :status 400}
             (not     (string? user-agent))                  {:body :invalid-request/user-agent-missing                     :status 400}
             (not     (phone-number-valid-f))                {:body :illegal-client-behaviour/invalid-phone-number-received :status 403}
             (boolean (too-many-attempts-by-phone-number-f)) {:body :too-many-requests/too-many-attempts-by-phone-number    :status 429}
             (boolean (too-many-attempts-by-ip-address-f))   {:body :too-many-requests/too-many-attempts-by-ip-address      :status 429}
             (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed              :status 520}
             (not     (phone-number-registered-f))           {:body :standard-activity/unregistered-phone-number-received   :status 200}
             (not     (phone-number-verified-f))             {:body :standard-activity/unverified-phone-number-received     :status 200}
             :verified-phone-number-received                 {:body :standard-activity/verified-phone-number-received       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn create-user-account
  ; @description
  ; For further information about this function, check the 'README.md' file.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:create-user-f (function)
  ;  :email-address-registered-f (function)
  ;  :email-address-valid-f (function)
  ;  :optional-check-f (function)(opt)
  ;  :password-valid-f (function)
  ;  :send-welcome-email-f (function)
  ;  :user-data-valid-f (function)
  ;  :user-logged-in-f (function)
  ;  :too-many-attempts-by-email-address-f (function)
  ;  :too-many-attempts-by-ip-address-f (function)
  ;  :too-many-failure-by-email-address-f (function)}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address,
  ;   :invalid-request/missing-user-agent,
  ;   :illegal-client-behaviour/invalid-email-address-received,
  ;   :illegal-client-behaviour/invalid-password-received,
  ;   :illegal-client-behaviour/invalid-user-data-received,
  ;   :illegal-client-behaviour/user-already-logged-in,
  ;   :illegal-client-behaviour/email-address-already-registered,
  ;   :server-error/unable-to-create-user-account,
  ;   :too-many-requests/too-many-attempts-by-email-address,
  ;   :too-many-requests/too-many-attempts-ip-address,
  ;   :too-many-requests/too-many-failure-email-address,
  ;   :standard-activity/unable-to-send-welcome-email,
  ;   :standard-activity/user-account-created,
  ;   :unknown-error/optional-check-stage-failed
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [create-user-account-f
                   email-address-registered-f
                   email-address-valid-f
                   optional-check-f
                   password-valid-f
                   send-welcome-email-f
                   user-data-valid-f
                   user-logged-in-f
                   too-many-attempts-by-email-address-f
                   too-many-attempts-by-ip-address-f
                   too-many-failure-by-email-address-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                   {:body :invalid-request/ip-address-missing                        :status 400}
             (not     (string? user-agent))                   {:body :invalid-request/user-agent-missing                        :status 400}
             (not     (email-address-valid-f))                {:body :illegal-client-behaviour/invalid-email-address-received   :status 403}
             (not     (password-valid-f))                     {:body :illegal-client-behaviour/invalid-password-received        :status 403}
             (not     (user-data-valid-f))                    {:body :illegal-client-behaviour/invalid-user-data-received       :status 403}
             (boolean (user-logged-in-f))                     {:body :illegal-client-behaviour/user-already-logged-in           :status 403}
             (boolean (email-address-registered-f))           {:body :illegal-client-behaviour/email-address-already-registered :status 403}
             (boolean (too-many-attempts-by-email-address-f)) {:body :too-many-requests/too-many-attempts-by-email-address      :status 429}
             (boolean (too-many-attempts-by-ip-address-f))    {:body :too-many-requests/too-many-attempts-by-ip-address         :status 429}
             (boolean (too-many-failure-by-ip-address-f))     {:body :too-many-requests/too-many-failure-by-ip-address          :status 429}
             (and optional-check-f (not (optional-check-f)))  {:body :unknown-error/optional-check-stage-failed                 :status 520}
             :creating-user-account (cond (not (send-welcome-email-f))  {:body :standard-activity/unable-to-send-welcome-email :status 200}
                                          (not (create-user-account-f)) {:body :server-error/unable-to-create-user-account     :status 500}
                                          :user-account-created         {:body :standard-activity/user-account-created         :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn drop-user-session
  ; @description
  ; For further information about this function, check the 'README.md' file.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:optional-check-f (function)(opt)}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :standard-activity/user-session-dropped,
  ;   :unknown-error/optional-check-stage-failed
  ;  :status (integer)
  ;   200}
  [_ {:keys [optional-check-f]}]
  (cond (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed :status 520}
        :dropping-user-session                          {:body :standard-activity/user-session-dropped    :status 200 :session {}}))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn remove-user-account
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:password (string)
  ;    :ruv-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :session (map)
  ;  :status (integer)}
  [request {:keys [email-address-verified-f
                   password-correct-f
                   remove-user-f
                   security-code-expired-f
                   security-code-incorrect-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-required-from-another-ip-address-f
                   send-goodbye-email-f
                   session-valid-f
                   user-id-known-f
                   too-much-attempts-by-ip-address-f
                   too-much-failure-by-ip-address-f
                   too-much-attempts-by-user-id-f]}]

  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - Invalid remove user verification code has been received despite the client-side form validation.
  ; - No remove user verification code has been sent in the past 24 hours.
  ; - The remove user verification code is required from another IP address.
  ; - No user ID found in the actual session found in the request.
  ; - No user account is found with the user ID found in the actual session.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Removing user account attempted with the user ID found in the actual session at least 15 times in the last 10 minutes.
  ; - Removing user account attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Removing user account failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect password has been received.
  ; - Incorrect remove user verification code has been received.
  ; - The remove user verification code is expired.
  ; - User account is successfully removed.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot remove the user related documents.
  ; - Unable to send goodbye email.
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
             (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
             (not     (security-code-valid-f))                            {:body :security-code-invalid                          :status 403}
             (not     (security-code-sent-f))                             {:body :no-security-code-sent-in-timeframe             :status 403}
             (boolean (security-code-required-from-another-ip-address-f)) {:body :security-code-required-from-another-ip-address :status 403}
             (not     (session-valid-f))                                  {:body :invalid-session                                :status 403}
             (not     (user-id-known-f))                                  {:body :user-id-unknown                                :status 403}
             (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
             (boolean (too-much-attempts-by-user-id-f))                   {:body :too-much-attempts-by-user-id                   :status 429}
             (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
             (boolean (too-much-failure-by-ip-address-f))                 {:body :too-much-failure-by-ip-address                 :status 429}
             (not     (password-correct-f))                               {:body :password-incorrect                             :status 200}
             (not     (security-code-correct-f))                          {:body :security-code-incorrect                        :status 200}
             (boolean (security-code-expired-f))                          {:body :security-code-expired                          :status 200}
             :removing-account-account (cond (not (send-goodbye-email-f))  {:body :unable-to-send-goodbye-email  :status 500}
                                             (not (remove-user-account-f)) {:body :unable-to-remove-user-account :status 500}
                                             :user-account-removed         {:body :user-account-removed          :status 200 :session {}}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-eas-code-authenticated-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)}}
  ; @param (integer) eal-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [request {:keys []}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address login code sending attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address login code sending attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The email address login code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the email address login code.
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                {:body :user-agent-missing              :status 400}
             (not     (string? ip-address))                {:body :ip-address-missing              :status 400}
             (not     (session-valid-f))                   {:body :invalid-session                 :status 403}
             (not     (user-id-known-f))                   {:body :user-id-unknown                 :status 403}
             (not     (email-address-verified-f))          {:body :email-address-not-verified      :status 403}
             (boolean (too-much-attempts-by-user-id-f))    {:body :too-much-attempts-by-user-id    :status 429}
             (boolean (too-much-attempts-by-ip-address-f)) {:body :too-much-attempts-by-ip-address :status 429}
             :sending-eas-code (cond (not (send-eas-code-f)) {:body :unable-to-send-eas-code :status 500}
                                     :eas-code-sent          {:body :eas-code-sent           :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-eas-code-unauthenticated-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)}}
  ; @param (integer) eal-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [request {:keys []}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address login code sending attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address login code sending attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The email address login code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the email address login code.
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                   {:body :user-agent-missing                 :status 400}
             (not     (string? ip-address))                   {:body :ip-address-missing                 :status 400}
             (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}
             (not     (email-address-valid-f))                {:body :email-address-invalid              :status 403}
             (not     (email-address-known-f))                {:body :email-address-unknown              :status 403}
             (not     (email-address-verified-f))             {:body :email-address-not-verified         :status 403}
             (boolean (too-much-attempts-by-email-address-f)) {:body :too-much-attempts-by-email-address :status 429}
             (boolean (too-much-attempts-by-ip-address-f))    {:body :too-much-attempts-by-ip-address    :status 429}
             :sending-eas-code (cond (not (send-eas-code-f)) {:body :unable-to-send-eas-code :status 500}
                                     :eas-code-sent          {:body :eas-code-sent           :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-eav-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)}}
  ; @param (integer) eav-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [email-address]} :transit-params :as request} eav-code]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is already verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address verification code sending attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address verification code sending attempted by the same IP address at least 30 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The email address verification code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the verification code.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/email-address email-address} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(too-much-attempts-by-email-address? [] (services.log/user-activity-illegal? {:allowed-count 14 :max-age 600000} {:action :sending-eav-code :request {:transit-params {:email-address email-address}}}))
               (too-much-attempts-by-ip-address?    [] (services.log/user-activity-illegal? {:allowed-count 29 :max-age 600000} {:action :sending-eav-code :client  {:ip-address ip-address}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (not     (email-address-valid-f))                {:body :email-address-invalid              :status 403}
                    (not     (email-address-known-f))                {:body :email-address-unknown              :status 403}
                    (-> user-account :email-address-verified?)                  {:body :email-address-already-verified     :status 403}
                    (boolean (too-much-attempts-by-email-address-f)) {:body :too-much-attempts-by-email-address :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    :sending-eav-code (if-let [eav-code-email-sent? (actions.side-effects/send-eav-code-email! (:id user-account) 600000 eav-code)]
                                              {:body :eav-code-sent          :status 200}
                                              {:body :eav-code-sending-error :status 500})))))

(defn send-eav-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":eav-code-sent"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [eav-code (audit/generate-security-code protocols.config/SECURITY-CODE-LENGTH)
        response (send-eav-code-f request eav-code)]
       (services.log/reg-user-activity! {:action :sending-eav-code :request request :response response :meta-data {:eav-code eav-code}})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-pnl-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:phone-number (string)}}
  ; @param (integer) pnl-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [phone-number]} :transit-params :as request} pnl-code]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid phone number has been received despite the client-side form validation.
  ; - No user account is found with the received phone number.
  ; - The email address of the found user account is NOT verified (the phone number
  ;   -based login method is only available after the user has verified their email address).
  ; - The phone number of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address login code sending attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address login code sending attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The email address login code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the email address login code.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/phone-number phone-number} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(too-much-attempts-by-phone-number? [] (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :sending-pnl-code :request {:transit-params {:phone-number phone-number}}}))
               (too-much-attempts-by-ip-address?   [] (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :sending-pnl-code :client  {:ip-address ip-address}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (-> phone-number protocols.utils/phone-number-valid? not) {:body :phone-number-invalid              :status 403}
                    (-> user-account not)                                     {:body :phone-number-unknown              :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (-> user-account :phone-number-verified? not)             {:body :phone-number-not-verified         :status 403}
                    (too-much-attempts-by-phone-number?)                      {:body :too-much-attempts-by-phone-number :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    :sending-pnl-code (if-let [pnl-code-sms-sent? (actions.side-effects/send-pnl-code-sms! (:id user-account) 600000 pnl-code)]
                                              {:body :pnl-code-sent          :status 200}
                                              {:body :pnl-code-sending-error :status 500})))))

(defn send-pnl-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:phone-number (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":pnl-code-sent"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [pnl-code (audit/generate-security-code protocols.config/SECURITY-CODE-LENGTH)
        response (send-pnl-code-f request pnl-code)]
       (services.log/reg-user-activity! {:action :sending-pnl-code :request request :response response :meta-data {:pnl-code pnl-code}})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-pnv-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:phone-number (string)}}
  ; @param (integer) pnv-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [phone-number]} :transit-params :as request} pnv-code]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid phone number has been received despite the client-side form validation.
  ; - No user account is found with the received phone number.
  ; - The phone number of the found user account is already verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Phone number verification code sending attempted with the received phone number at least 15 times in the last 10 minutes.
  ; - Phone number verification code sending attempted by the same IP address at least 30 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The phone number verification code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the verification code.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/phone-number phone-number} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(too-much-attempts-by-phone-number? [] (services.log/user-activity-illegal? {:allowed-count 14 :max-age 600000} {:action :sending-pnv-code :request {:transit-params {:phone-number phone-number}}}))
               (too-much-attempts-by-ip-address?   [] (services.log/user-activity-illegal? {:allowed-count 29 :max-age 600000} {:action :sending-pnv-code :client  {:ip-address ip-address}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (-> phone-number protocols.utils/phone-number-valid? not) {:body :phone-number-invalid              :status 403}
                    (-> user-account not)                                     {:body :phone-number-unknown              :status 403}
                    (-> user-account :phone-number-verified?)                 {:body :phone-number-already-verified     :status 403}
                    (too-much-attempts-by-phone-number?)                      {:body :too-much-attempts-by-phone-number :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    :sending-pnv-code (if-let [pnv-code-sms-sent? (actions.side-effects/send-pnv-code-sms! (:id user-account) 600000 pnv-code)]
                                              {:body :pnv-code-sent          :status 200}
                                              {:body :pnv-code-sending-error :status 500})))))

(defn send-pnv-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:phone-number (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":pnv-code-sent"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [pnv-code (audit/generate-security-code protocols.config/SECURITY-CODE-LENGTH)
        response (send-pnv-code-f request pnv-code)]
       (services.log/reg-user-activity! {:action :sending-pnv-code :request request :response response :meta-data {:pnv-code pnv-code}})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-ruv-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}}
  ; @param (integer) ruv-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:user-account/keys [id]} :session :as request} ruv-code]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - No user ID found in the actual session found in the request.
  ; - No user account is found with the user ID found in the actual session.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Remove user verification code sending attempted with the user ID found in the actual session at least 15 times in the last 10 minutes.
  ; - Remove user verification code sending attempted by the same IP address at least 30 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The remove user verification code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the verification code.
  (let [user-account (mongo-db/get-document-by-id "user-data/accounts" id {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(too-much-attempts-by-user-id?    [] (services.log/user-activity-illegal? {:allowed-count 14 :max-age 600000} {:action :sending-ruv-code :request {:session {:user-account/id id}}}))
               (too-much-attempts-by-ip-address? [] (services.log/user-activity-illegal? {:allowed-count 29 :max-age 600000} {:action :sending-pnv-code :client  {:ip-address ip-address}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (-> id nil?)                                   {:body :invalid-session                 :status 403}
                    (-> user-account not)                          {:body :user-id-unknown                 :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (too-much-attempts-by-user-id?)                {:body :too-much-attempts-by-user-id    :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    :sending-ruv-code (if-let [ruv-code-email-sent? (actions.side-effects/send-ruv-code-email! (:id user-account) 600000 ruv-code)]
                                              {:body :ruv-code-sent          :status 200}
                                              {:body :ruv-code-sending-error :status 500})))))

(defn send-ruv-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":ruv-code-sent"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [ruv-code (audit/generate-security-code protocols.config/SECURITY-CODE-LENGTH)
        response (send-ruv-code-f request ruv-code)]
       (services.log/reg-user-activity! {:action :sending-ruv-code :request request :response response :meta-data {:ruv-code ruv-code}})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-upnv-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}}
  ; @param (integer) upnv-code
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:user-account/keys [id]} :session :as request} upnv-code]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - No user ID found in the actual session found in the request.
  ; - No user account is found with the user ID found in the actual session.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Remove user verification code sending attempted with the user ID found in the actual session at least 15 times in the last 10 minutes.
  ; - Remove user verification code sending attempted by the same IP address at least 30 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ;
  ; HTTP status 200 (standard activity):
  ; - The remove user verification code has been sent.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the verification code.
  (let [user-account (mongo-db/get-document-by-id "user-data/accounts" id {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(too-much-attempts-by-user-id?    [] (services.log/user-activity-illegal? {:allowed-count 14 :max-age 600000} {:action :sending-ruv-code :request {:session {:user-account/id id}}}))
               (too-much-attempts-by-ip-address? [] (services.log/user-activity-illegal? {:allowed-count 29 :max-age 600000} {:action :sending-pnv-code :client  {:ip-address ip-address}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (-> id nil?)                                   {:body :invalid-session                 :status 403}
                    (-> user-account not)                          {:body :user-id-unknown                 :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (too-much-attempts-by-user-id?)                {:body :too-much-attempts-by-user-id    :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    :sending-upnv-code (if-let [upnv-code-sms-sent? (actions.side-effects/send-upnv-code-sms! (:id user-account) 600000 upnv-code)]
                                               {:body :upnv-code-sent          :status 200}
                                               {:body :upnv-code-sending-error :status 500})))))

(defn send-upnv-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":upnv-code-sent"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [upnv-code (audit/generate-security-code protocols.config/SECURITY-CODE-LENGTH)
        response  (send-upnv-code-f request upnv-code)]
       (services.log/reg-user-activity! {:action :sending-upnv-code :request request :response response :meta-data {:upnv-code upnv-code}})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-email-address-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:email-address (string)
  ;    :password (string)
  ;    :ueav-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [email-address]} :transit-params {:user-account/keys [id]} :session :as request}])

(defn update-email-address
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:email-address (string)
  ;    :password (string)
  ;    :ueav-code (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;  :status (integer)}
  [request]
  (let [response (update-email-address-f request)]
       (services.log/reg-user-activity! {:action :updating-email-address :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-phone-number-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)
  ;    :upnv-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [phone-number]} :transit-params :as request}])

(defn update-phone-number
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)
  ;    :upnv-code (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;  :status (integer)}
  [request]
  (let [response (update-phone-number-f request)]
       (services.log/reg-user-activity! {:action :updating-phone-number :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-eal-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:eal-code (string)
  ;    :email-address (string)
  ;    :password (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :session (map)
  ;  :status (integer)}
  [{{:keys [eal-code email-address password]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - Invalid email address login code has been received despite the client-side form validation.
  ; - No email address login code has been sent in the past 24 hours.
  ; - The email address login code is required from another IP address.
  ; - The received email address login code has been already verified.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is NOT verified.
  ; - The received password is incorrect (in addition to the password verification, verifying the email address login code
  ;   requires the password in order to provide protection against by-passing the password verifying form attacks).
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address login code verification attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address login code verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Email address login code verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect email address login code has been received.
  ; - The email address login code is expired.
  ; - Correct email address login code has been received.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/email-address email-address} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)
        log-entry    (services.log/get-user-activity {:max-age 86400000} {:action :sending-eal-code :request {:transit-params {:email-address email-address}}})] ; Last :sending-eal-code log entry from the past 24 hours.
       (letfn [(check-password-f                    [%] (= % (hash/hmac-sha256 password email-address)))
               (check-eal-code-expiration-f         [%] (-> % time/timestamp-string->epoch-ms time/epoch-ms-age (> 600000)))
               (too-much-attempts-by-email-address? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eal-code :request {:transit-params {:email-address email-address}}}))
               (too-much-attempts-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-eal-code :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?     []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eal-code :client  {:ip-address ip-address} :response {:body {:$ne :eal-code-verified}}}))
               (eal-code-already-verified?          []  (services.log/user-activity-illegal? {:allowed-count   0 :max-age 600000} {:action :verifying-eal-code :request {:transit-params {:eal-code eal-code}} :response {:body :eal-code-verified}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (not     (email-address-valid-f))                {:body :email-address-invalid              :status 403}
                    (-> eal-code protocols.utils/security-code-valid? not)      {:body :eal-code-invalid                          :status 403}
                    (-> log-entry not)                                          {:body :no-eal-code-sent-in-the-past-24hrs        :status 403}
                    (-> log-entry :client :ip-address (not= ip-address))        {:body :eal-code-required-from-another-ip-address :status 403}
                    (eal-code-already-verified?)                                {:body :eal-code-already-verified                 :status 403}
                    (not     (email-address-known-f))                {:body :email-address-unknown              :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (-> user-account :password check-password-f not)            {:body :password-incorrect                        :status 403}
                    (boolean (too-much-attempts-by-email-address-f)) {:body :too-much-attempts-by-email-address :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                           {:body :too-much-failure-by-ip-address            :status 429}
                    (-> log-entry :meta-data :eal-code str (not= eal-code))     {:body :eal-code-incorrect                        :status 200}
                    (-> log-entry :registered-at check-eal-code-expiration-f)   {:body :eal-code-expired                          :status 200}
                    ; Successful email address login code verification logs the user in by adding user session to the server response.
                    :eal-code-verified (let [user-session (session.env/create-user-session (:id user-account))]
                                            {:body :eal-code-correct :status 200 :session user-session})))))

(defn verify-eal-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:eal-code (string)
  ;    :email-address (string)
  ;    :password (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":eal-code-correct", ":eal-code-expired", ":eal-code-incorrect"
  ;  :session (map)
  ;  :status (integer)
  ;   200, 400, 403, 429}
  [request]
  (let [response (verify-eal-code-f request)]
       (services.log/reg-user-activity! {:action :verifying-eal-code :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-eanp-pair-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)(opt)
  ;    :password (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [email-address password]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Password verification attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Password verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Password verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect password has been received.
  ; - Correct password has been received.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the email address login code.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/email-address email-address} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(check-password-f                    [%] (= % (hash/hmac-sha256 password email-address)))
               (too-much-attempts-by-email-address? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eanp-pair :request {:transit-params {:email-address email-address}}}))
               (too-much-attempts-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-eanp-pair :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?     []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eanp-pair :client  {:ip-address ip-address} :outcome {:$ne :eanp-pair-verified}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (not     (email-address-valid-f))                {:body :email-address-invalid              :status 403}
                    (not     (email-address-known-f))                {:body :email-address-unknown              :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (boolean (too-much-attempts-by-email-address-f)) {:body :too-much-attempts-by-email-address :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                           {:body :too-much-failure-by-ip-address     :status 429}
                    (-> user-account :password check-password-f not)            {:body :password-incorrect                 :status 200}
                    ; The server automatically sends the email address login code in case of correct password has been received.
                    :eanp-pair-verified (if-let [eal-code-sent? (-> request send-eal-code :status (= 200))]
                                                {:body :eanp-pair-correct       :status 200}
                                                {:body :unable-to-send-eal-code :status 500})))))

(defn verify-eanp-pair
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:email-address (string)
  ;    :password (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":eanp-pair-correct", ":eanp-pair-incorrect"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [response (verify-eanp-pair-f request)]
       (services.log/reg-user-activity! {:action :verifying-eanp-pair :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-eav-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:eav-code (string)
  ;    :email-address (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [eav-code email-address]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid email address has been received despite the client-side form validation.
  ; - Invalid email address verification code has been received despite the client-side form validation.
  ; - No email address verification code has been sent in the past 24 hours.
  ; - The email address verification code is required from another IP address.
  ; - The received email address verification code has been already verified.
  ; - No user account is found with the received email address.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Email address verification code verification attempted with the received email address at least 15 times in the last 10 minutes.
  ; - Email address verification code verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Email address verification code verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect email address verification code has been received.
  ; - The email address verification code is expired.
  ; - Correct email address verification code has been receive and the email address is now verified.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot update the user account document.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/email-address email-address} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)
        log-entry    (services.log/get-user-activity {:max-age 86400000} {:action :sending-eav-code :request {:transit-params {:email-address email-address}}})] ; Last :sending-eav-code log entry from the past 24 hours.
       (letfn [(check-eav-code-expiration-f         [%] (-> % time/timestamp-string->epoch-ms time/epoch-ms-age (> 600000)))
               (mark-email-address-as-verified!     []  (account.side-effects/update-user-account! (:id user-account) {:email-address-verified? true}))
               (too-much-attempts-by-email-address? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eav-code :request {:transit-params {:email-address email-address}}}))
               (too-much-attempts-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-eav-code :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?     []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-eav-code :client  {:ip-address ip-address} :response {:body {:$ne :eav-code-verified}}}))
               (eav-code-already-verified?          []  (services.log/user-activity-illegal? {:allowed-count   0 :max-age 600000} {:action :verifying-eav-code :request {:transit-params {:eav-code eav-code}} :response {:body :eav-code-verified}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (not     (email-address-valid-f))                {:body :email-address-invalid              :status 403}
                    (-> eav-code protocols.utils/security-code-valid? not)      {:body :eav-code-invalid                          :status 403}
                    (-> log-entry not)                                          {:body :no-eav-code-sent-in-the-past-24hrs        :status 403}
                    (-> log-entry :client :ip-address (not= ip-address))        {:body :eav-code-required-from-another-ip-address :status 403}
                    (eav-code-already-verified?)                                {:body :eav-code-already-verified                 :status 403}
                    (not     (email-address-known-f))                {:body :email-address-unknown              :status 403}
                    (-> user-account :email-address-verified?)                  {:body :email-address-already-verified            :status 403}
                    (boolean (too-much-attempts-by-email-address-f)) {:body :too-much-attempts-by-email-address :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                           {:body :too-much-failure-by-ip-address            :status 429}
                    (-> log-entry :meta-data :eav-code str (not= eav-code))     {:body :eav-code-incorrect                        :status 200}
                    (-> log-entry :registered-at check-eav-code-expiration-f)   {:body :eav-code-expired                          :status 200}
                    :eav-code-verified (if (mark-email-address-as-verified!)
                                           {:body :eav-code-correct                       :status 200}
                                           {:body :unable-to-update-user-account-document :status 500})))))

(defn verify-eav-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:eav-code (string)
  ;    :email-address (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":eav-code-correct", ":eav-code-expired", ":eav-code-incorrect"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [response (verify-eav-code-f request)]
       (services.log/reg-user-activity! {:action :verifying-eav-code :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-pin-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:pin-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [pin-code]} :transit-params {:user-account/keys [id]} :session :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - Invalid PIN code has been received despite the client-side form validation.
  ; - No user ID found in the actual session found in the request.
  ; - No user account is found with the user ID found in the actual session.
  ; - The email address of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - PIN code verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - PIN code verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - PIN code verification attempted with the user ID found in the actual session at least 5 times in the last 5 minutes
  ;   (PIN code verification failures are much common than other security code verification failures, and not declared as
  ;    illegal behaviour).
  ; - Incorrect PIN code has been received.
  ; - Correct PIN code has been received.
  (let [user-account (mongo-db/get-document-by-id "user-data/accounts" id {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(check-pin-code-f                 [%] (= % (hash/hmac-sha256 pin-code (:email-address user-account))))
               (too-much-attempts-by-user-id?    []  (services.log/user-activity-illegal? {:allowed-count   4 :max-age 300000} {:action :verifying-pin-code :request {:session {:user-account/id id}}}))
               (too-much-attempts-by-ip-address? []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-pin-code :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?  []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pin-code :client  {:ip-address ip-address} :response {:body {:$ne :pin-code-verified}}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (-> pin-code protocols.utils/pin-code-valid? not) {:body :pin-code-invalid                :status 403}
                    (-> id nil?)                                      {:body :invalid-session                 :status 403}
                    (-> user-account not)                             {:body :user-id-unknown                 :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                 {:body :too-much-failure-by-ip-address  :status 429}
                    (too-much-attempts-by-user-id?)                   {:body :too-much-attempts-by-user-id    :status 200}
                    (-> user-account :pin-code check-pin-code-f not)  {:body :pin-code-incorrect              :status 200}
                    :pin-code-verified                                {:body :pin-code-correct                :status 200}))))

(defn verify-pin-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:session (map)
  ;   {:user-account/id (string)}
  ;  :transit-params (map)
  ;   {:pin-code (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":pin-code-correct", ":pin-code-incorrect"
  ;  :status (integer)
  ;   200, 400, 403, 429}
  [request]
  (let [response (verify-pin-code-f request)]
       (services.log/reg-user-activity! {:action :verifying-pin-code :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-pnl-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)
  ;    :pnl-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :session (map)
  ;  :status (integer)}
  [{{:keys [password phone-number pnl-code]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid phone number has been received despite the client-side form validation.
  ; - Invalid phone number login code has been received despite the client-side form validation.
  ; - No phone number login code has been sent in the past 24 hours.
  ; - The phone number login code is required from another IP address.
  ; - The received phone number login code has been already verified.
  ; - No user account is found with the received phone number.
  ; - The email address of the found user account is NOT verified (the phone number
  ;   -based login method is only available after the user has verified their email address).
  ; - The phone number of the found user account is NOT verified.
  ; - The received password is incorrect (in addition to the password verification, verifying the phone number login code
  ;   requires the password in order to provide protection against by-passing the password verifying form attacks).
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Phone number login code verification attempted with the received phone number at least 15 times in the last 10 minutes.
  ; - Phone number login code verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Phone number login code verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect phone number login code has been received.
  ; - The phone number login code is expired.
  ; - Correct phone number login code has been received.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/phone-number phone-number} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)
        log-entry    (services.log/get-user-activity {:max-age 86400000} {:action :sending-pnl-code :request {:transit-params {:phone-number phone-number}}})] ; Last :sending-pnl-code log entry from the past 24 hours.
       (letfn [(check-password-f                   [%] (= % (hash/hmac-sha256 password (:email-address user-account))))
               (check-pnl-code-expiration-f        [%] (-> % time/timestamp-string->epoch-ms time/epoch-ms-age (> 600000)))
               (too-much-attempts-by-phone-number? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnl-code :request {:transit-params {:phone-number phone-number}}}))
               (too-much-attempts-by-ip-address?   []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-pnl-code :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnl-code :client  {:ip-address ip-address} :response {:body {:$ne :pnl-code-verified}}}))
               (pnl-code-already-verified?         []  (services.log/user-activity-illegal? {:allowed-count   0 :max-age 600000} {:action :verifying-pnl-code :request {:transit-params {:pnl-code pnl-code}} :response {:body :pnl-code-verified}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (-> phone-number protocols.utils/phone-number-valid? not) {:body :phone-number-invalid                      :status 403}
                    (-> pnl-code protocols.utils/security-code-valid? not)    {:body :pnl-code-invalid                          :status 403}
                    (-> log-entry not)                                        {:body :no-pnl-code-sent-in-the-past-24hrs        :status 403}
                    (-> log-entry :client :ip-address (not= ip-address))      {:body :pnl-code-required-from-another-ip-address :status 403}
                    (pnl-code-already-verified?)                              {:body :pnl-code-already-verified                 :status 403}
                    (-> user-account not)                                     {:body :phone-number-unknown                      :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (-> user-account :phone-number-verified? not)             {:body :phone-number-not-verified                 :status 403}
                    (-> user-account :password check-password-f not)          {:body :password-incorrect                        :status 403}
                    (too-much-attempts-by-phone-number?)                      {:body :too-much-attempts-by-phone-number         :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                         {:body :too-much-failure-by-ip-address            :status 429}
                    (-> log-entry :meta-data :pnl-code str (not= pnl-code))   {:body :pnl-code-incorrect                        :status 200}
                    (-> log-entry :registered-at check-pnl-code-expiration-f) {:body :pnl-code-expired                          :status 200}
                    ; Successful phone number login code verification logs the user in by adding user session to the server response.
                    :pnl-code-verified (let [user-session (session.env/create-user-session (:id user-account))]
                                            {:body :pnl-code-correct :status 200 :session user-session})))))

(defn verify-pnl-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)
  ;    :pnl-code (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":pnl-code-correct", ":pnl-code-expired", ":pnl-code-incorrect"
  ;  :session (map)
  ;  :status (integer)
  ;   200, 400, 403, 429}
  [request]
  (let [response (verify-pnl-code-f request)]
       (services.log/reg-user-activity! {:action :verifying-pnl-code :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-pnnp-pair-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)(opt)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [password phone-number]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid phone number has been received despite the client-side form validation.
  ; - No user account is found with the received phone number.
  ; - The email address of the found user account is NOT verified (the phone number
  ;   -based login method is only available after the user has verified their email address).
  ; - The phone number of the found user account is NOT verified.

  ; HTTP status 429 (too much attempts by the client):
  ; - Password verification attempted with the received phone number at least 15 times in the last 10 minutes.
  ; - Password verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Password verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect password has been received.
  ; - Correct password has been received.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot send the email address login code.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/phone-number phone-number} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)]
       (letfn [(check-password-f                   [%] (= % (hash/hmac-sha256 password (:email-address user-account))))
               (too-much-attempts-by-phone-number? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnnp-pair :request {:transit-params {:phone-number phone-number}}}))
               (too-much-attempts-by-ip-address?   []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-pnnp-pair :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnnp-pair :client  {:ip-address ip-address} :response {:body {:$ne :pnnp-pair-verified}}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (-> phone-number protocols.utils/phone-number-valid? not) {:body :phone-number-invalid              :status 403}
                    (-> user-account not)                                     {:body :phone-number-unknown              :status 403}
                    (not     (email-address-verified-f))                         {:body :email-address-not-verified                     :status 403}
                    (-> user-account :phone-number-verified? not)             {:body :phone-number-not-verified         :status 403}
                    (too-much-attempts-by-phone-number?)                      {:body :too-much-attempts-by-phone-number :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                         {:body :too-much-failure-by-ip-address    :status 429}
                    (-> user-account :password check-password-f not)          {:body :password-incorrect                :status 200}
                    ; The server automatically sends phone number login code in case of correct password has been received.
                    :pnnp-pair-verified (if-let [pnl-code-sent? (-> request send-pnl-code :status (= 200))]
                                                {:body :pnnp-pair-correct       :status 200}
                                                {:body :unable-to-send-pnl-code :status 500})))))

(defn verify-pnnp-pair
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:password (string)
  ;    :phone-number (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":pnnp-pair-correct", ":pnnp-pair-incorrect"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [response (verify-pnnp-pair-f request)]
       (services.log/reg-user-activity! {:action :verifying-pnnp-pair :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-pnv-code-f
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:phone-number (string)
  ;    :pnv-code (string)}}
  ;
  ; @return (map)
  ; {:body (keyword)
  ;  :status (integer)}
  [{{:keys [phone-number pnv-code]} :transit-params :as request}]
  ; HTTP status 400 (invalid request):
  ; - No user agent found in the request.
  ; - No IP address found in the request.
  ;
  ; HTTP status 403 (illegal client behaviour):
  ; - The user already logged in and has a valid session.
  ; - Invalid phone number has been received despite the client-side form validation.
  ; - Invalid phone number verification code has been received despite the client-side form validation.
  ; - No phone number verification code has been sent in the past 24 hours.
  ; - The phone number verification code is required from another IP address.
  ; - The received phone number verification code has been already verified.
  ; - No user account is found with the received phone number.
  ; - The phone number of the found user account is NOT verified.
  ;
  ; HTTP status 429 (too much attempts by the client):
  ; - Phone number verification code verification attempted with the received phone number at least 15 times in the last 10 minutes.
  ; - Phone number verification code verification attempted by the same IP address at least 500 times in the last 10 minutes (an IP address
  ;   could belong to a workplace with different client devices with a shared IP address).
  ; - Phone number verification code verification failed by the same IP address at least 15 times in the last 10 minutes.
  ;
  ; HTTP status 200 (standard activity):
  ; - Incorrect phone number verification code has been received.
  ; - The phone number verification code is expired.
  ; - Correct phone number verification code has been received and the phone number is now verified.
  ;
  ; HTTP status 500 (server error):
  ; - The server cannot update the user account document.
  (let [user-account (mongo-db/get-document-by-query "user-data/accounts" {:user-account/phone-number phone-number} {:prototype-f map/remove-namespace})
        ip-address   (http/request->ip-address request)
        user-agent   (http/request->user-agent request)
        log-entry    (services.log/get-user-activity {:max-age 86400000} {:action :sending-pnv-code :request {:transit-params {:phone-number phone-number}}})] ; Last :sending-pnv-code log entry from the past 24 hours.
       (letfn [(check-pnv-code-expiration-f        [%] (-> % time/timestamp-string->epoch-ms time/epoch-ms-age (> 600000)))
               (mark-phone-number-as-verified!     []  (account.side-effects/update-user-account! (:id user-account) {:phone-number-verified? true}))
               (too-much-attempts-by-phone-number? []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnv-code :request {:transit-params {:phone-number phone-number}}}))
               (too-much-attempts-by-ip-address?   []  (services.log/user-activity-illegal? {:allowed-count 499 :max-age 600000} {:action :verifying-pnv-code :client  {:ip-address ip-address}}))
               (too-much-failure-by-ip-address?    []  (services.log/user-activity-illegal? {:allowed-count  14 :max-age 600000} {:action :verifying-pnv-code :client  {:ip-address ip-address} :response {:body {:$ne :pnv-code-verified}}}))
               (pnv-code-already-verified?         []  (services.log/user-activity-illegal? {:allowed-count   0 :max-age 600000} {:action :verifying-pnv-code :request {:transit-params {:pnv-code pnv-code}} :response {:body :pnv-code-verified}}))]
              (cond (not     (string? user-agent))                               {:body :user-agent-missing                             :status 400}
                    (not     (string? ip-address))                               {:body :ip-address-missing                             :status 400}
                    (boolean (user-logged-in-f))                     {:body :user-already-logged-in             :status 403}

                    (-> phone-number protocols.utils/phone-number-valid? not) {:body :phone-number-invalid                      :status 403}
                    (-> pnv-code protocols.utils/security-code-valid? not)    {:body :pnv-code-invalid                          :status 403}
                    (-> log-entry not)                                        {:body :no-pnv-code-sent-in-the-past-24hrs        :status 403}
                    (-> log-entry :client :ip-address (not= ip-address))      {:body :pnv-code-required-from-another-ip-address :status 403}
                    (pnv-code-already-verified?)                              {:body :pnl-code-already-verified                 :status 403}
                    (-> user-account not)                                     {:body :phone-number-unknown                      :status 403}
                    (-> user-account :phone-number-verified?)                 {:body :phone-number-already-verified             :status 403}
                    (too-much-attempts-by-phone-number?)                      {:body :too-much-attempts-by-phone-number         :status 429}
                    (boolean (too-much-attempts-by-ip-address-f))                {:body :too-much-attempts-by-ip-address                :status 429}
                    (too-much-failure-by-ip-address?)                         {:body :too-much-failure-by-ip-address            :status 429}
                    (-> log-entry :meta-data :pnv-code str (not= pnv-code))   {:body :pnv-code-incorrect                        :status 200}
                    (-> log-entry :registered-at check-pnv-code-expiration-f) {:body :pnv-code-expired                          :status 200}
                    :pnv-code-verified (if (mark-phone-number-as-verified!)
                                           {:body :pnv-code-correct                       :status 200}
                                           {:body :unable-to-update-user-account-document :status 500})))))

(defn verify-pnv-code
  ; @ignore
  ;
  ; @param (map) request
  ; {:transit-params (map)
  ;   {:pnv-code (string)
  ;    :phone-number (string)}}
  ;
  ; @return (map)
  ; {:body (string)
  ;   ":client-error", ":server-error", ":pnv-code-correct", ":pnv-code-expired", ":pnv-code-incorrect"
  ;  :status (integer)
  ;   200, 400, 403, 429, 500}
  [request]
  (let [response (verify-pnv-code-f request)]
       (services.log/reg-user-activity! {:action :verifying-pnv-code :request request :response response})
       (http/text-wrap response {:hide-errors? true})))

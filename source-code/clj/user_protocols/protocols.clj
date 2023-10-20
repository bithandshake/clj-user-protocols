
(ns user-protocols.protocols
    (:require [http.api :as http]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn check-user-contact
  ; @description
  ; Security protocol function for checking a user contact such as an email address or a phone number whether it is registered and/or verified.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-contact-verified-f (function)
  ;   Must return TRUE if the received email address / phone number is verified.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (check-user-contact {...} {...})
  ;
  ; @example
  ; (check-user-contact {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         ip-address    (-> request :remote-addr)]
  ;        (check-user-contact request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                     :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                     :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                     :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
  ;                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :standard-activity/user-contact-verified :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address has been received),
  ;   :standard-activity/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :standard-activity/unverified-user-contact-received
  ;   (Registered but unverified email address / phone number has been received),
  ;   :standard-activity/verified-user-contact-received
  ;   (Registered and verified email address / phone number has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-contact-verified-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                   {:body :invalid-request/ip-address-missing                     :status 400}
             (not     (string? user-agent))                   {:body :invalid-request/user-agent-missing                     :status 400}
             (not     (user-contact-valid-f))                 {:body :illegal-client-behaviour/invalid-user-contact-received :status 403}
             (boolean (client-rate-limit-exceeded-f))         {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))           {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (and optional-check-f (not (optional-check-f)))  {:body :unknown-error/optional-check-stage-failed              :status 520}
             (not     (user-contact-registered-f))            {:body :standard-activity/unregistered-user-contact-received   :status 200}
             (not     (user-contact-verified-f))              {:body :standard-activity/unverified-user-contact-received     :status 200}
             :verified-user-contact-received                  {:body :standard-activity/verified-user-contact-received       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn create-user-account
  ; @description
  ; Security protocol function for creating a user account that is identified by an email address or a phone number and protected by a password.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :create-user-account-f (function)
  ;   Must return TRUE if the user account has been successfully created.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :send-welcome-message-f (function)
  ;   Must return TRUE if the welcome email / SMS has been successfully sent.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-data-valid-f (function)
  ;   Must return TRUE if the received user data is valid.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-password-valid-f (function)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (create-user-account {...} {...})
  ;
  ; @example
  ; (create-user-account {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         ip-address    (-> request :remote-addr)
  ;         user-data     (-> request :params)
  ;         user-session  (-> request :session)]
  ;        (create-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                      :create-user-account-f        #(my-database/create-user-account!                   user-data)
  ;                                      :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                      :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                      :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
  ;                                      :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                      :send-welcome-message-f       #(my-email-service/send-welcome-email!               email-address)
  ;                                      :user-data-valid-f            #(my-validator/user-data-valid?                      user-data)
  ;                                      :user-logged-in-f             #(my-validator/user-session-valid?                   user-session)
  ;                                      :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :standard-activity/user-account-created :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :illegal-client-behaviour/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :illegal-client-behaviour/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :illegal-client-behaviour/user-already-logged-in
  ;   (The user has been already logged in and has a valid session),
  ;   :illegal-client-behaviour/registered-user-contact-received
  ;   (Registered email address / phone number has been received),
  ;   :server-error/unable-to-create-user-account
  ;   (The server cannot create the user account),
  ;   :standard-activity/unable-to-send-welcome-message
  ;   (The server cannot send the welcome email / SMS to the user. It's not declared
  ;    as an error because before the contact validation, the given email address /
  ;    phone number might contain typos or might not working),
  ;   :standard-activity/user-account-created
  ;   (The server has been successfully created the user account),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   create-user-account-f
                   optional-check-f
                   send-welcome-message-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-data-valid-f
                   user-logged-in-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                   {:body :invalid-request/ip-address-missing                        :status 400}
             (not     (string? user-agent))                   {:body :invalid-request/user-agent-missing                        :status 400}
             (not     (user-contact-valid-f))                 {:body :illegal-client-behaviour/invalid-user-contact-received    :status 403}
             (not     (user-password-valid-f))                {:body :illegal-client-behaviour/invalid-user-password-received   :status 403}
             (not     (user-data-valid-f))                    {:body :illegal-client-behaviour/invalid-user-data-received       :status 403}
             (boolean (user-logged-in-f))                     {:body :illegal-client-behaviour/user-already-logged-in           :status 403}
             (boolean (user-contact-registered-f))            {:body :illegal-client-behaviour/registered-user-contact-received :status 403}
             (boolean (client-rate-limit-exceeded-f))         {:body :too-many-requests/client-rate-limit-exceeded              :status 429}
             (boolean (user-rate-limit-exceeded-f))           {:body :too-many-requests/user-rate-limit-exceeded                :status 429}
             (and optional-check-f (not (optional-check-f)))  {:body :unknown-error/optional-check-stage-failed                 :status 520}
             :creating-user-account (cond (not (send-welcome-message-f)) {:body :standard-activity/unable-to-send-welcome-message :status 200}
                                          (not (create-user-account-f))  {:body :server-error/unable-to-create-user-account       :status 500}
                                          :user-account-created          {:body :standard-activity/user-account-created           :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn drop-user-session
  ; @description
  ; Security protocol function for dropping a user session.
  ; Performs various security checks before returns a HTTP response indicating the result of the checks.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.}
  ;
  ; @usage
  ; (drop-user-session {...} {...})
  ;
  ; @example
  ; (drop-user-session {...} {...})
  ; =>
  ; {:body :standard-activity/user-session-dropped :status 200 :session {}}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (drop-user-session request {}))
  ; =>
  ; {:body :standard-activity/user-session-dropped :status 200 :session {}}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :standard-activity/user-session-dropped
  ;   (The user session has been removed successfully),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 520}
  [_ {:keys [optional-check-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (string? ip-address))                      {:body :invalid-request/ip-address-missing        :status 400}
             (not (string? user-agent))                      {:body :invalid-request/user-agent-missing        :status 400}
             (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed :status 520}
             :dropping-user-session                          {:body :standard-activity/user-session-dropped    :status 200 :session {}})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn remove-user-account
  ; @description
  ; Security protocol function for a user account removal that requires a user password and security code verification.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :remove-user-account-f (function)
  ;   Must return TRUE if the user account has been successfully removed.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-required-from-another-ip-address-f (function)
  ;   Must return TRUE if the received security code has been required from another IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :send-goodbye-message-f (function)
  ;   Must return TRUE if the goodbye email / SMS has been successfully sent.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-password-correct-f (function)
  ;   Must return TRUE if the received user password matches the stored one.
  ;  :user-password-valid-f (function)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (remove-user-account {...} {...})
  ;
  ; @example
  ; (remove-user-account {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         ip-address    (-> request :remote-addr)
  ;         user-id       (-> request :session :user-id)
  ;         user-session  (-> request :session)]
  ;        (remove-user-account request {:client-rate-limit-exceeded-f                     #(my-log-service/too-many-attempts-by-ip-address?                ip-address)
  ;                                      :remove-user-account-f                            #(my-database/remove-user-account!                               user-id)
  ;                                      :security-code-correct-f                          #(my-database/security-code-matches?                             user-id security-code)
  ;                                      :security-code-expired-f                          #(my-database/security-code-expired?                             user-id)
  ;                                      :security-code-required-from-another-ip-address-f #(my-log-service/security-code-required-from-another-ip-address? user-id ip-address)
  ;                                      :security-code-sent-f                             #(my-database/security-code-sent?                                user-id)
  ;                                      :security-code-valid-f                            #(my-validator/security-code-valid?                              security-code)
  ;                                      :send-goodbye-message-f                           #(my-email-service/send-goodbye-email!                           user-id)
  ;                                      :user-id-exists-f                                 #(my-database/user-id-exists?                                    user-id)
  ;                                      :user-logged-in-f                                 #(my-validator/user-session-valid?                               user-session)
  ;                                      :user-password-correct-f                          #(my-database/user-password-matches?                             user-password)
  ;                                      :user-password-valid-f                            #(my-validator/user-password-valid?                              user-password)
  ;                                      :user-rate-limit-exceeded-f                       #(my-log-service/too-many-attempts-by-user-id?                   user-id)})))
  ; =>
  ; {:body :standard-activity/user-account-removed :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :illegal-client-behaviour/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :illegal-client-behaviour/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :illegal-client-behaviour/security-code-required-from-another-ip-address
  ;   (The received security code has been required from another IP address),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :server-error/unable-to-remove-user-account
  ;   (The server cannot remove the user account),
  ;   :server-error/unable-to-send-goodbye-message
  ;   (The server cannot send the goodbye email / SMS to the user),
  ;   :standard-activity/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :standard-activity/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :standard-activity/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :standard-activity/user-account-removed
  ;   (The server has been successfully removed the user account),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :session (map)
  ;   {}
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   remove-user-account-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-required-from-another-ip-address-f
                   send-goodbye-message-f
                   user-id-exists-f
                   user-logged-in-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                               {:body :invalid-request/user-agent-missing                                      :status 400}
             (not     (string? ip-address))                               {:body :invalid-request/ip-address-missing                                      :status 400}
             (not     (user-password-valid-f))                            {:body :illegal-client-behaviour/invalid-user-password-received                 :status 403}
             (not     (security-code-valid-f))                            {:body :illegal-client-behaviour/invalid-security-code-received                 :status 403}
             (not     (security-code-sent-f))                             {:body :illegal-client-behaviour/no-security-code-sent-in-timeframe             :status 403}
             (boolean (security-code-required-from-another-ip-address-f)) {:body :illegal-client-behaviour/security-code-required-from-another-ip-address :status 403}
             (not     (user-id-exists-f))                                 {:body :illegal-client-behaviour/user-id-not-exists                             :status 403}
             (not     (user-logged-in-f))                                 {:body :illegal-client-behaviour/user-not-logged-in                             :status 403}
             (boolean (client-rate-limit-exceeded-f))                     {:body :too-many-requests/client-rate-limit-exceeded                            :status 429}
             (boolean (user-rate-limit-exceeded-f))                       {:body :too-many-requests/user-rate-limit-exceeded                              :status 429}
             (and optional-check-f (not (optional-check-f)))              {:body :unknown-error/optional-check-stage-failed                               :status 520}
             (not     (user-password-correct-f))                          {:body :standard-activity/incorrect-user-password-received                      :status 200}
             (not     (security-code-correct-f))                          {:body :standard-activity/incorrect-security-code-received                      :status 200}
             (boolean (security-code-expired-f))                          {:body :standard-activity/expired-security-code-received                        :status 200}
             :removing-account-account (cond (not (send-goodbye-message-f)) {:body :server-error/unable-to-send-goodbye-message :status 500}
                                             (not (remove-user-account-f))  {:body :server-error/unable-to-remove-user-account  :status 500}
                                             :user-account-removed          {:body :standard-activity/user-account-removed      :status 200 :session {}}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-authenticated-f
  ; @description
  ; Security protocol function for sending a security code via email or SMS to an authenticated (logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :send-security-code-f (function)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (send-security-code-authenticated {...} {...})
  ;
  ; @example
  ; (send-security-code-authenticated {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address   (-> request :remote-addr)
  ;         user-id      (-> request :session :user-id)
  ;         user-session (-> request :session)]
  ;        (send-security-code-authenticated request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                                   :send-security-code-f         #(my-email-service/send-security-code-email!      user-id)
  ;                                                   :user-id-exists-f             #(my-database/user-id-exists?                     user-id)
  ;                                                   :user-logged-in-f             #(my-validator/user-session-valid?                user-session)
  ;                                                   :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :standard-activity/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :standard-activity/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   send-security-code-f
                   user-id-exists-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                  {:body :invalid-request/user-agent-missing                :status 400}
             (not     (string? ip-address))                  {:body :invalid-request/ip-address-missing                :status 400}
             (not     (user-id-exists-f))                    {:body :illegal-client-behaviour/user-id-not-exists       :status 403}
             (not     (user-logged-in-f))                    {:body :illegal-client-behaviour/user-not-logged-in       :status 403}
             (boolean (client-rate-limit-exceeded-f))        {:body :too-many-requests/client-rate-limit-exceeded      :status 429}
             (boolean (user-rate-limit-exceeded-f))          {:body :too-many-requests/user-rate-limit-exceeded        :status 429}
             (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed         :status 520}
             :sending-security-code (cond (not (send-security-code-f)) {:body :server-error/unable-to-send-security-code :status 500}
                                     :security-code-sent               {:body :standard-activity/security-code-sent      :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-unauthenticated-f
  ; @description
  ; Security protocol function for sending a security code via email or SMS to an unauthenticated (not logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :send-security-code-f (function)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (send-security-code-unauthenticated {...} {...})
  ;
  ; @example
  ; (send-security-code-unauthenticated {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         ip-address    (-> request :remote-addr)
  ;         user-session  (-> request :session)]
  ;        (send-security-code-unauthenticated request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                                     :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                                     :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                                     :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                                     :user-logged-in-f             #(my-validator/user-session-valid?                   user-session)
  ;                                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :standard-activity/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :illegal-client-behaviour/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :illegal-client-behaviour/user-already-logged-in
  ;   (The user is logged in / authenticated),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :standard-activity/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   send-security-code-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                   {:body :invalid-request/user-agent-missing                          :status 400}
             (not     (string? ip-address))                   {:body :invalid-request/ip-address-missing                          :status 400}
             (not     (user-contact-valid-f))                 {:body :illegal-client-behaviour/invalid-user-contact-received      :status 403}
             (not     (user-contact-registered-f))            {:body :illegal-client-behaviour/unregistered-user-contact-received :status 403}
             (boolean (user-logged-in-f))                     {:body :illegal-client-behaviour/user-already-logged-in             :status 403}
             (boolean (client-rate-limit-exceeded-f))         {:body :too-many-requests/client-rate-limit-exceeded                :status 429}
             (boolean (user-rate-limit-exceeded-f))           {:body :too-many-requests/user-rate-limit-exceeded                  :status 429}
             (and optional-check-f (not (optional-check-f)))  {:body :unknown-error/optional-check-stage-failed                   :status 520}
             :sending-security-code (cond (not (send-security-code-f)) {:body :server-error/unable-to-send-security-code :status 500}
                                     :security-code-sent               {:body :standard-activity/security-code-sent      :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-contact
  ; @description
  ; Security protocol function for a user account's email address or phone number update that requires a user password and security code verification.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-required-from-another-ip-address-f (function)
  ;   Must return TRUE if the received security code has been required from another IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :update-user-contact-f (function)
  ;   Must return TRUE if the user's email address / phone number has been successfully updated.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-password-correct-f (function)
  ;   Must return TRUE if the received user password matches the stored one.
  ;  :user-password-valid-f (function)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (update-user-contact {...} {...})
  ;
  ; @example
  ; (update-user-contact {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         ip-address    (-> request :remote-addr)
  ;         user-id       (-> request :session :user-id)
  ;         user-session  (-> request :session)]
  ;        (update-user-contact request {:client-rate-limit-exceeded-f                     #(my-log-service/too-many-attempts-by-ip-address?                ip-address)
  ;                                      :user-contact-registered-f                        #(my-database/email-address-registered?                          email-address)
  ;                                      :user-contact-valid-f                             #(my-validator/email-address-valid?                              email-address)
  ;                                      :user-password-correct-f                          #(my-database/user-password-matches?                             user-password)
  ;                                      :user-password-valid-f                            #(my-validator/user-password-valid?                              user-password)
  ;                                      :security-code-correct-f                          #(my-database/security-code-matches?                             user-id security-code)
  ;                                      :security-code-expired-f                          #(my-database/security-code-expired?                             user-id)
  ;                                      :security-code-required-from-another-ip-address-f #(my-log-service/security-code-required-from-another-ip-address? user-id ip-address)
  ;                                      :security-code-sent-f                             #(my-database/security-code-sent?                                user-id)
  ;                                      :security-code-valid-f                            #(my-validator/security-code-valid?                              security-code)
  ;                                      :user-id-exists-f                                 #(my-database/user-id-exists?                                    user-id)
  ;                                      :user-logged-in-f                                 #(my-validator/user-session-valid?                               user-session)
  ;                                      :user-rate-limit-exceeded-f                       #(my-log-service/too-many-attempts-by-user-id?                   user-id)})))
  ; =>
  ; {:body :standard-activity/user-contact-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :illegal-client-behaviour/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :illegal-client-behaviour/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :illegal-client-behaviour/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :illegal-client-behaviour/registered-user-contact-received
  ;   (Registered email address /phone number has been received),
  ;   :illegal-client-behaviour/security-code-required-from-another-ip-address
  ;   (The received security code has been required from another IP address),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :server-error/unable-to-update-user-contact
  ;   (The server cannot update the user's email address / phone number),
  ;   :standard-activity/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :standard-activity/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :standard-activity/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :standard-activity/user-contact-updated
  ;   (The server has been successfully updated the user's email address / phone number),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-required-from-another-ip-address-f
                   update-user-contact-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-id-exists-f
                   user-logged-in-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                               {:body :invalid-request/user-agent-missing                                      :status 400}
             (not     (string? ip-address))                               {:body :invalid-request/ip-address-missing                                      :status 400}
             (not     (user-contact-valid-f))                             {:body :illegal-client-behaviour/invalid-user-contact-received                  :status 403}
             (not     (user-password-valid-f))                            {:body :illegal-client-behaviour/invalid-user-password-received                 :status 403}
             (not     (security-code-valid-f))                            {:body :illegal-client-behaviour/invalid-security-code-received                 :status 403}
             (boolean (user-contact-registered-f))                        {:body :illegal-client-behaviour/registered-user-contact-received               :status 403}
             (not     (security-code-sent-f))                             {:body :illegal-client-behaviour/no-security-code-sent-in-timeframe             :status 403}
             (boolean (security-code-required-from-another-ip-address-f)) {:body :illegal-client-behaviour/security-code-required-from-another-ip-address :status 403}
             (not     (user-id-exists-f))                                 {:body :illegal-client-behaviour/user-id-not-exists                             :status 403}
             (not     (user-logged-in-f))                                 {:body :illegal-client-behaviour/user-not-logged-in                             :status 403}
             (boolean (client-rate-limit-exceeded-f))                     {:body :too-many-requests/client-rate-limit-exceeded                            :status 429}
             (boolean (user-rate-limit-exceeded-f))                       {:body :too-many-requests/user-rate-limit-exceeded                              :status 429}
             (and optional-check-f (not (optional-check-f)))              {:body :unknown-error/optional-check-stage-failed                               :status 520}
             (not     (user-password-correct-f))                          {:body :standard-activity/incorrect-user-password-received                      :status 200}
             (not     (security-code-correct-f))                          {:body :standard-activity/incorrect-security-code-received                      :status 200}
             (boolean (security-code-expired-f))                          {:body :standard-activity/expired-security-code-received                        :status 200}
             :updating-user-contact (cond (not (update-user-contact-f)) {:body :server-error/unable-to-update-user-contact :status 500}
                                          :user-contact-updated         {:body :standard-activity/user-contact-updated     :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-account
  ; @description
  ; Security protocol function for updating a user account.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :update-user-account-f (function)
  ;   Must return TRUE if the user account has been successfully updated.
  ;  :user-data-valid-f (function)
  ;   Must return TRUE if the received user data is valid.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (update-user-account {...} {...})
  ;
  ; @example
  ; (update-user-account {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address   (-> request :remote-addr)
  ;         user-data    (-> request :params)
  ;         user-id      (-> request :session :user-id)
  ;         user-session (-> request :session)]
  ;        (update-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                      :update-user-account-f        #(my-database/update-user-account!                user-id user-data)
  ;                                      :user-data-valid-f            #(my-validator/user-data-valid?                   user-data)
  ;                                      :user-id-exists-f             #(my-database/user-id-exists?                     user-id)
  ;                                      :user-logged-in-f             #(my-validator/user-session-valid?                user-session)
  ;                                      :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :standard-activity/user-account-update :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :server-error/unable-to-update-user-account
  ;   (The server cannot update the user account),
  ;   :standard-activity/user-account-updated
  ;   (The server has been successfully updated the user account),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   update-user-account-f
                   user-data-valid-f
                   user-id-exists-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? ip-address))                  {:body :invalid-request/ip-address-missing                  :status 400}
             (not     (string? user-agent))                  {:body :invalid-request/user-agent-missing                  :status 400}
             (not     (user-id-exists-f))                    {:body :illegal-client-behaviour/user-id-not-exists         :status 403}
             (not     (user-logged-in-f))                    {:body :illegal-client-behaviour/user-not-logged-in         :status 403}
             (not     (user-data-valid-f))                   {:body :illegal-client-behaviour/invalid-user-data-received :status 403}
             (boolean (client-rate-limit-exceeded-f))        {:body :too-many-requests/client-rate-limit-exceeded        :status 429}
             (boolean (user-rate-limit-exceeded-f))          {:body :too-many-requests/user-rate-limit-exceeded          :status 429}
             (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed           :status 520}
             :updating-user-account (cond (not (update-user-account-f)) {:body :server-error/unable-to-update-user-account :status 500}
                                          :user-account-updated         {:body :standard-activity/user-account-updated     :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-authenticated-f
  ; @description
  ; Security protocol function for verifying a security code sent via email or SMS to an authenticated (logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-required-from-another-ip-address-f (function)
  ;   Must return TRUE if the received security code has been required from another IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (verify-security-code-authenticated {...} {...})
  ;
  ; @example
  ; (verify-security-code-authenticated {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [security-code (-> request :params :security-code)
  ;         ip-address    (-> request :remote-addr)
  ;         user-id       (-> request :session :user-id)
  ;         user-session  (-> request :session)]
  ;        (verify-security-code-authenticated request {:client-rate-limit-exceeded-f                     #(my-log-service/too-many-attempts-by-ip-address?                ip-address)
  ;                                                     :security-code-correct-f                          #(my-database/security-code-matches?                             user-id security-code)
  ;                                                     :security-code-expired-f                          #(my-database/security-code-expired?                             user-id)
  ;                                                     :security-code-required-from-another-ip-address-f #(my-log-service/security-code-required-from-another-ip-address? user-id ip-address)
  ;                                                     :security-code-sent-f                             #(my-database/security-code-sent?                                user-id)
  ;                                                     :security-code-valid-f                            #(my-validator/security-code-valid?                              security-code)
  ;                                                     :user-id-exists-f                                 #(my-database/user-id-exists?                                    user-id)
  ;                                                     :user-logged-in-f                                 #(my-validator/user-session-valid?                               user-session)
  ;                                                     :user-rate-limit-exceeded-f                       #(my-log-service/too-many-attempts-by-user-id?                   user-id)})))
  ; =>
  ; {:body :standard-activity/correct-security-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :illegal-client-behaviour/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :illegal-client-behaviour/security-code-required-from-another-ip-address
  ;   (The received security code has been required from another IP address),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :standard-activity/correct-security-code-received
  ;   (Correct security code has been received),
  ;   :standard-activity/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :standard-activity/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   security-code-correct-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-required-from-another-ip-address-f
                   user-id-exists-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                               {:body :invalid-request/user-agent-missing                                      :status 400}
             (not     (string? ip-address))                               {:body :invalid-request/ip-address-missing                                      :status 400}
             (not     (security-code-valid-f))                            {:body :illegal-client-behaviour/invalid-security-code-received                 :status 403}
             (not     (security-code-sent-f))                             {:body :illegal-client-behaviour/no-security-code-sent-in-timeframe             :status 403}
             (boolean (security-code-required-from-another-ip-address-f)) {:body :illegal-client-behaviour/security-code-required-from-another-ip-address :status 403}
             (not     (user-id-exists-f))                                 {:body :illegal-client-behaviour/user-id-not-exists                             :status 403}
             (not     (user-logged-in-f))                                 {:body :illegal-client-behaviour/user-not-logged-in                             :status 403}
             (boolean (client-rate-limit-exceeded-f))                     {:body :too-many-requests/client-rate-limit-exceeded                            :status 429}
             (boolean (user-rate-limit-exceeded-f))                       {:body :too-many-requests/user-rate-limit-exceeded                              :status 429}
             (and optional-check-f (not (optional-check-f)))              {:body :unknown-error/optional-check-stage-failed                               :status 520}
             (not     (security-code-correct-f))                          {:body :standard-activity/incorrect-security-code-received                      :status 200}
             (boolean (security-code-expired-f))                          {:body :standard-activity/expired-security-code-received                        :status 200}
             :security-code-verified                                      {:body :standard-activity/correct-security-code-received                        :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-unauthenticated-f
  ; @description
  ; Security protocol function for verifying a security code sent via email or SMS to an unauthenticated (not logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-required-from-another-ip-address-f (function)
  ;   Must return TRUE if the received security code has been required from another IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-password-correct-f (function)
  ;   Must return TRUE if the received user password matches the stored one.
  ;  :user-password-valid-f (function)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (verify-security-code-unauthenticated {...} {...})
  ;
  ; @example
  ; (verify-security-code-unauthenticated {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         ip-address    (-> request :remote-addr)
  ;         user-session  (-> request :session)]
  ;        (verify-security-code-unauthenticated request {:client-rate-limit-exceeded-f                     #(my-log-service/too-many-attempts-by-ip-address?                ip-address)
  ;                                                       :user-password-correct-f                          #(my-database/user-password-matches?                             user-password)
  ;                                                       :user-password-valid-f                            #(my-validator/user-password-valid?                              user-password)
  ;                                                       :security-code-correct-f                          #(my-database/security-code-matches?                             email-address security-code)
  ;                                                       :security-code-expired-f                          #(my-database/security-code-expired?                             email-address)
  ;                                                       :security-code-required-from-another-ip-address-f #(my-log-service/security-code-required-from-another-ip-address? email-address ip-address)
  ;                                                       :security-code-sent-f                             #(my-database/security-code-sent?                                email-address)
  ;                                                       :security-code-valid-f                            #(my-validator/security-code-valid?                              security-code)
  ;                                                       :user-contact-registered-f                        #(my-database/email-address-registered?                          email-address)
  ;                                                       :user-contact-valid-f                             #(my-validator/email-address-valid?                              email-address)
  ;                                                       :user-logged-in-f                                 #(my-validator/user-session-valid?                               user-session)})))
  ;                                                       :user-rate-limit-exceeded-f                       #(my-log-service/too-many-attempts-by-email-address?             email-address)})))
  ; =>
  ; {:body :standard-activity/correct-security-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :illegal-client-behaviour/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :illegal-client-behaviour/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :illegal-client-behaviour/security-code-required-from-another-ip-address
  ;   (The received security code has been required from another IP address),
  ;   :illegal-client-behaviour/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :illegal-client-behaviour/user-already-logged-in
  ;   (The user is logged in / authenticated),
  ;   :standard-activity/correct-security-code-received
  ;   (Correct security code has been received),
  ;   :standard-activity/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :standard-activity/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :standard-activity/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-required-from-another-ip-address-f
                   security-code-sent-f
                   security-code-valid-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-logged-in-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                               {:body :invalid-request/user-agent-missing                                      :status 400}
             (not     (string? ip-address))                               {:body :invalid-request/ip-address-missing                                      :status 400}
             (not     (user-contact-valid-f))                             {:body :illegal-client-behaviour/invalid-user-contact-received                  :status 403}
             (not     (user-password-valid-f))                            {:body :illegal-client-behaviour/invalid-user-password-received                 :status 403}
             (not     (security-code-valid-f))                            {:body :illegal-client-behaviour/invalid-security-code-received                 :status 403}
             (not     (security-code-sent-f))                             {:body :illegal-client-behaviour/no-security-code-sent-in-timeframe             :status 403}
             (boolean (security-code-required-from-another-ip-address-f)) {:body :illegal-client-behaviour/security-code-required-from-another-ip-address :status 403}
             (not     (user-contact-registered-f))                        {:body :illegal-client-behaviour/unregistered-user-contact-received             :status 403}
             (boolean (user-logged-in-f))                                 {:body :illegal-client-behaviour/user-already-logged-in                         :status 403}
             (boolean (client-rate-limit-exceeded-f))                     {:body :too-many-requests/client-rate-limit-exceeded                            :status 429}
             (boolean (user-rate-limit-exceeded-f))                       {:body :too-many-requests/user-rate-limit-exceeded                              :status 429}
             (and optional-check-f (not (optional-check-f)))              {:body :unknown-error/optional-check-stage-failed                               :status 520}
             (not     (user-password-correct-f))                          {:body :standard-activity/incorrect-user-password-received                      :status 200}
             (not     (security-code-correct-f))                          {:body :standard-activity/incorrect-security-code-received                      :status 200}
             (boolean (security-code-expired-f))                          {:body :standard-activity/expired-security-code-received                        :status 200}
             :security-code-verified                                      {:body :standard-activity/correct-security-code-received                        :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-password
  ; @description
  ; Security protocol function for verifying a user password and optionally sending an MFA security code.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :send-security-code-f (function)(opt)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-contact-verified-f (function)
  ;   Must return TRUE if the received email address / phone number is verified.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-password-correct-f (function)
  ;   Must return TRUE if the received user password matches the stored one.
  ;  :user-password-valid-f (function)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (verify-user-password {...} {...})
  ;
  ; @example
  ; (verify-user-password {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         ip-address    (-> request :remote-addr)
  ;         user-session  (-> request :session)]
  ;        (verify-user-password request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                       :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                       :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                       :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                       :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
  ;                                       :user-password-correct-f      #(my-database/user-password-matches?                 user-password)
  ;                                       :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                       :user-logged-in-f             #(my-validator/user-session-valid?                   user-session)
  ;                                       :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :standard-activity/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :illegal-client-behaviour/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :illegal-client-behaviour/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :illegal-client-behaviour/unverified-user-contact-received
  ;   (Unverified email address / phone number has been received),
  ;   :illegal-client-behaviour/user-already-logged-in
  ;   (The user is logged in / authenticated),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :standard-activity/correct-user-password-received
  ;   (Correct user password has been received),
  ;   :standard-activity/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :standard-activity/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   send-security-code-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-contact-verified-f
                   user-password-correct-f
                   user-password-valid-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))                  {:body :invalid-request/user-agent-missing                          :status 400}
             (not     (string? ip-address))                  {:body :invalid-request/ip-address-missing                          :status 400}
             (not     (user-contact-valid-f))                {:body :illegal-client-behaviour/invalid-user-contact-received      :status 403}
             (not     (user-password-valid-f))               {:body :illegal-client-behaviour/invalid-user-password-received     :status 403}
             (not     (user-contact-registered-f))           {:body :illegal-client-behaviour/unregistered-user-contact-received :status 403}
             (not     (user-contact-verified-f))             {:body :illegal-client-behaviour/unverified-user-contact-received   :status 403}
             (boolean (user-logged-in-f))                    {:body :illegal-client-behaviour/user-already-logged-in             :status 403}
             (boolean (client-rate-limit-exceeded-f))        {:body :too-many-requests/client-rate-limit-exceeded                :status 429}
             (boolean (user-rate-limit-exceeded-f))          {:body :too-many-requests/user-rate-limit-exceeded                  :status 429}
             (and optional-check-f (not (optional-check-f))) {:body :unknown-error/optional-check-stage-failed                   :status 520}
             (not     (user-password-correct-f))             {:body :standard-activity/incorrect-user-password-received          :status 200}
             :user-password-verified (cond (not send-security-code-f)   {:body :standard-activity/correct-user-password-received :status 200}
                                           (not (send-security-code-f)) {:body :server-error/unable-to-send-security-code        :status 500}
                                           :security-code-sent          {:body :standard-activity/security-code-sent             :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-pin-code
  ; @description
  ; Security protocol function for verifying a user PIN code.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
  ;  :optional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :user-id-exists-f (function)
  ;   Must return TRUE the user ID exists.
  ;  :user-logged-in-f (function)
  ;   Must return TRUE the request contains a valid (logged-in) user session.
  ;  :user-pin-code-correct-f (function)
  ;   Must return TRUE if the received user PIN code matches the stored one.
  ;  :user-pin-code-valid-f (function)
  ;   Must return TRUE if the received user PIN code is valid.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (verify-user-pin-code {...} {...})
  ;
  ; @example
  ; (verify-user-pin-code {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [user-pin-code (-> request :params :pin-code)
  ;         ip-address    (-> request :remote-addr)
  ;         user-id       (-> request :session :user-id)
  ;         user-session  (-> request :session)]
  ;        (verify-user-pin-code request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                       :user-id-exists-f             #(my-database/user-id-exists?                     user-id)
  ;                                       :user-logged-in-f             #(my-validator/user-session-valid?                user-session)
  ;                                       :user-pin-code-correct-f      #(my-database/user-pin-code-matches?              user-pin-code)
  ;                                       :user-pin-code-valid-f        #(my-validator/user-pin-code-valid?               user-pin-code)
  ;                                       :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :standard-activity/correct-user-pin-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/missing-ip-address
  ;   (No IP address has been found in the request),
  ;   :invalid-request/missing-user-agent
  ;   (No user agent has been found in the request),
  ;   :illegal-client-behaviour/invalid-user-pin-code-received
  ;   (Invalid user PIN code has been received),
  ;   :illegal-client-behaviour/user-id-not-exists
  ;   (The user ID does not exist),
  ;   :illegal-client-behaviour/user-not-logged-in
  ;   (The user is not logged in / unauthenticated),
  ;   :standard-activity/correct-user-pin-code-received
  ;   (Correct user PIN code has been received),
  ;   :standard-activity/incorrect-user-pin-code-received
  ;   (Incorrect user PIN code has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/optional-check-stage-failed
  ;   (The optional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [client-rate-limit-exceeded-f
                   optional-check-f
                   pin-code-correct-f
                   pin-code-valid-f
                   user-id-exists-f
                   user-logged-in-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not     (string? user-agent))           {:body :invalid-request/user-agent-missing                      :status 400}
             (not     (string? ip-address))           {:body :invalid-request/ip-address-missing                      :status 400}
             (not     (user-pin-code-valid-f))        {:body :illegal-client-behaviour/invalid-user-pin-code-received :status 403}
             (not     (user-id-exists-f))             {:body :illegal-client-behaviour/user-id-not-exists             :status 403}
             (not     (user-logged-in-f))             {:body :illegal-client-behaviour/user-not-logged-in             :status 403}
             (boolean (client-rate-limit-exceeded-f)) {:body :too-many-requests/client-rate-limit-exceeded            :status 429}
             (boolean (user-rate-limit-exceeded-f))   {:body :too-many-requests/user-rate-limit-exceeded              :status 429}
             (not     (user-pin-code-correct-f))      {:body :standard-activity/incorrect-user-pin-code-received      :status 200}
             :user-pin-code-verified                  {:body :standard-activity/correct-user-pin-code-received        :status 200})))

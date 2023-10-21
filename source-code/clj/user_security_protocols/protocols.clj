
(ns user-security-protocols.protocols
    (:require [audit.api :as audit]
              [http.api  :as http]
              [noop.api  :refer [return]]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn check-user-contact
  ; @description
  ; Security protocol function for checking a user contact such as an email address or a phone number whether it is registered and/or verified.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)]
  ;        (check-user-contact request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                     :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                     :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                     :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
  ;                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/user-contact-verified :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address has been received),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :performed-request/unverified-user-contact-received
  ;   (Registered but unverified email address / phone number has been received),
  ;   :performed-request/verified-user-contact-received
  ;   (Registered and verified email address / phone number has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-contact-verified-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                     :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                     :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received        :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed            :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed           :status 520}
             (not (user-contact-registered-f))                     {:body :performed-request/unregistered-user-contact-received   :status 200}
             (not (user-contact-verified-f))                       {:body :performed-request/unverified-user-contact-received     :status 200}
             :verified-user-contact-received                       {:body :performed-request/verified-user-contact-received       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn create-user-account
  ; @description
  ; Security protocol function for creating a user account that is identified by an email address or a phone number and protected by a password.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :send-welcome-message-f (function)
  ;   Must return TRUE if the welcome email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-data-valid-f (function)
  ;   Must return TRUE if the received user data is valid.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         user-data     (-> request :params)]
  ;        (create-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                      :create-user-account-f        #(my-database/create-user-account!                   user-data)
  ;                                      :send-welcome-message-f       #(my-email-service/send-welcome-email!               email-address)
  ;                                      :user-authenticated-f         #(my-validator/request-has-valid-session-valid?      request)
  ;                                      :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                      :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                      :user-data-valid-f            #(my-validator/user-data-valid?                      user-data)
  ;                                      :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                      :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/user-account-created :status 201}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :forbidden-request/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/registered-user-contact-received
  ;   (Registered email address / phone number has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-account-created
  ;   (The server has been successfully created the user account),
  ;   :server-error/unable-to-create-user-account
  ;   (The server cannot create the user account),
  ;   :server-error/unable-to-send-welcome-message
  ;   (The server cannot send the welcome email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   201, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   create-user-account-f
                   send-welcome-message-f
                   user-authenticated-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-data-valid-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                 :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                 :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received    :status 403}
             (not (user-password-valid-f))                         {:body :forbidden-request/invalid-user-password-received   :status 403}
             (not (user-data-valid-f))                             {:body :forbidden-request/invalid-user-data-received       :status 403}
             (boolean (user-authenticated-f))                      {:body :forbidden-request/user-authenticated               :status 403}
             (boolean (user-contact-registered-f))                 {:body :forbidden-request/registered-user-contact-received :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded       :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded         :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed        :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed       :status 520}
             (not (send-welcome-message-f))                        {:body :server-error/unable-to-send-welcome-message        :status 500}
             (not (create-user-account-f))                         {:body :server-error/unable-to-create-user-account         :status 500}
             :user-account-created                                 {:body :performed-request/user-account-created             :status 201})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn drop-user-session
  ; @description
  ; Security protocol function for dropping a user session.
  ; Performs various security checks before returns a HTTP response indicating the result of the checks.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
  ;  :user-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (drop-user-session {...} {...})
  ;
  ; @example
  ; (drop-user-session {...} {...})
  ; =>
  ; {:body :performed-request/user-session-dropped :status 200 :session {}}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-id    (-> request :session :user-id)]
  ;        (drop-user-session request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                    :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                    :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                    :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id}))
  ; =>
  ; {:body :performed-request/user-session-dropped :status 200 :session {}}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-session-dropped
  ;   (The user session has been removed successfully),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 429, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address           :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent           :status 400}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated       :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists            :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded   :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed  :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed :status 520}
             :user-session-dropped                                 {:body :performed-request/user-session-dropped       :status 200 :session {}})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn remove-user-account
  ; @description
  ; Security protocol function for a user account removal that requires a user password and security code verification.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :remove-user-account-f (function)
  ;   Must return TRUE if the user account has been successfully removed.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-ip-address-matches-f (function)
  ;   Must return TRUE if the received security code has been required from the same IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :send-goodbye-message-f (function)
  ;   Must return TRUE if the goodbye email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         user-id       (-> request :session :user-id)]
  ;        (remove-user-account request {:client-rate-limit-exceeded-f       #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                      :remove-user-account-f              #(my-database/remove-user-account!                                user-id)
  ;                                      :security-code-correct-f            #(my-database/security-code-matches?                              user-id security-code)
  ;                                      :security-code-expired-f            #(my-database/security-code-expired?                              user-id)
  ;                                      :security-code-ip-address-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                      :security-code-sent-f               #(my-database/security-code-sent?                                 user-id)
  ;                                      :security-code-valid-f              #(my-validator/security-code-valid?                               security-code)
  ;                                      :send-goodbye-message-f             #(my-email-service/send-goodbye-email!                            user-id)
  ;                                      :user-authenticated-f               #(my-validator/request-has-valid-session?                         request)
  ;                                      :user-exists-f                      #(my-database/user-id-exists?                                     user-id)
  ;                                      :user-password-correct-f            #(my-database/user-password-matches?                              user-password)
  ;                                      :user-password-valid-f              #(my-validator/user-password-valid?                               user-password)
  ;                                      :user-rate-limit-exceeded-f         #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-account-removed :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/security-code-ip-address-not-matches
  ;   (The received security code has been required from another IP address),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-account-removed
  ;   (The server has been successfully removed the user account),
  ;   :server-error/unable-to-remove-user-account
  ;   (The server cannot remove the user account),
  ;   :server-error/unable-to-send-goodbye-message
  ;   (The server cannot send the goodbye email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :session (map)
  ;   {}
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   remove-user-account-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-ip-address-matches-f
                   send-goodbye-message-f
                   user-authenticated-f
                   user-exists-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                     :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                     :status 400}
             (not (user-password-valid-f))                         {:body :forbidden-request/invalid-user-password-received       :status 403}
             (not (security-code-valid-f))                         {:body :forbidden-request/invalid-security-code-received       :status 403}
             (not (security-code-sent-f))                          {:body :forbidden-request/no-security-code-sent-in-timeframe   :status 403}
             (not (security-code-ip-address-matches-f))            {:body :forbidden-request/security-code-ip-address-not-matches :status 403}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated                 :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists                      :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (not (user-password-correct-f))                       {:body :unauthorized-request/incorrect-user-password-received  :status 401}
             (not (security-code-correct-f))                       {:body :unauthorized-request/incorrect-security-code-received  :status 401}
             (boolean (security-code-expired-f))                   {:body :unauthorized-request/expired-security-code-received    :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed            :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed           :status 520}
             (not (send-goodbye-message-f))                        {:body :server-error/unable-to-send-goodbye-message            :status 500}
             (not (remove-user-account-f))                         {:body :server-error/unable-to-remove-user-account             :status 500}
             :user-account-removed                                 {:body :performed-request/user-account-removed                 :status 200 :session {}})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-authenticated
  ; @description
  ; Security protocol function for sending a security code via email or SMS to an authenticated (logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :send-security-code-f (function)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-id    (-> request :session :user-id)]
  ;        (send-security-code-authenticated request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                                   :send-security-code-f         #(my-email-service/send-security-code-email!      user-id)
  ;                                                   :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                                   :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                                   :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :performed-request/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   send-security-code-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address           :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent           :status 400}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated       :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists            :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded   :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed  :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed :status 520}
             (not (send-security-code-f))                          {:body :server-error/unable-to-send-security-code    :status 500}
             :security-code-sent                                   {:body :performed-request/security-code-sent         :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-unauthenticated
  ; @description
  ; Security protocol function for sending a security code via email or SMS to an unauthenticated (not logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :send-security-code-f (function)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)]
  ;        (send-security-code-unauthenticated request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                                     :user-authenticated-f         #(my-validator/request-has-valid-session?            request)
  ;                                                     :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                                     :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                                     :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :forbidden-request/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   send-security-code-f
                   user-authenticated-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                   :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                   :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received      :status 403}
             (not (user-contact-registered-f))                     {:body :forbidden-request/unregistered-user-contact-received :status 403}
             (boolean (user-authenticated-f))                      {:body :forbidden-request/user-authenticated                 :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded         :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded           :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed          :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed         :status 520}
             (not (send-security-code-f))                          {:body :server-error/unable-to-send-security-code            :status 500}
             :security-code-sent                                   {:body :performed-request/security-code-sent                 :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-contact
  ; @description
  ; Security protocol function for a user account's email address or phone number update that requires a user password and security code verification.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-ip-address-matches-f (function)
  ;   Must return TRUE if the received security code has been required from the same IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :update-user-contact-f (function)
  ;   Must return TRUE if the user's email address / phone number has been successfully updated.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         user-id       (-> request :session :user-id)]
  ;        (update-user-contact request {:client-rate-limit-exceeded-f       #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                      :security-code-expired-f            #(my-database/security-code-expired?                              user-id)
  ;                                      :security-code-ip-address-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                      :security-code-sent-f               #(my-database/security-code-sent?                                 user-id)
  ;                                      :security-code-valid-f              #(my-validator/security-code-valid?                               security-code)
  ;                                      :update-user-contact-f              #(my-database/update-user-email-address!                          user-id email-address)
  ;                                      :user-contact-registered-f          #(my-database/email-address-registered?                           email-address)
  ;                                      :user-contact-valid-f               #(my-validator/email-address-valid?                               email-address)
  ;                                      :user-password-correct-f            #(my-database/user-password-matches?                              user-password)
  ;                                      :user-password-valid-f              #(my-validator/user-password-valid?                               user-password)
  ;                                      :security-code-correct-f            #(my-database/security-code-matches?                              user-id security-code)
  ;                                      :user-authenticated-f               #(my-validator/request-has-valid-session?                         request)
  ;                                      :user-exists-f                      #(my-database/user-id-exists?                                     user-id)
  ;                                      :user-rate-limit-exceeded-f         #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-contact-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/registered-user-contact-received
  ;   (Registered email address /phone number has been received),
  ;   :forbidden-request/security-code-ip-address-not-matches
  ;   (The received security code has been required from another IP address),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-contact-updated
  ;   (The server has been successfully updated the user's email address / phone number),
  ;   :server-error/unable-to-update-user-contact
  ;   (The server cannot update the user's email address / phone number),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-ip-address-matches-f
                   update-user-contact-f
                   user-authenticated-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-exists-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                     :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                     :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received        :status 403}
             (not (user-password-valid-f))                         {:body :forbidden-request/invalid-user-password-received       :status 403}
             (not (security-code-valid-f))                         {:body :forbidden-request/invalid-security-code-received       :status 403}
             (boolean (user-contact-registered-f))                 {:body :forbidden-request/registered-user-contact-received     :status 403}
             (not (security-code-sent-f))                          {:body :forbidden-request/no-security-code-sent-in-timeframe   :status 403}
             (not (security-code-ip-address-matches-f))            {:body :forbidden-request/security-code-ip-address-not-matches :status 403}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated                 :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists                      :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (not (user-password-correct-f))                       {:body :unauthorized-request/incorrect-user-password-received  :status 401}
             (not (security-code-correct-f))                       {:body :unauthorized-request/incorrect-security-code-received  :status 401}
             (boolean (security-code-expired-f))                   {:body :unauthorized-request/expired-security-code-received    :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed            :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed           :status 520}
             (not (update-user-contact-f))                         {:body :server-error/unable-to-update-user-contact             :status 500}
             :user-contact-updated                                 {:body :performed-request/user-contact-updated                 :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-account
  ; @description
  ; Security protocol function for updating a user account.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :update-user-account-f (function)
  ;   Must return TRUE if the user account has been successfully updated.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-data-valid-f (function)
  ;   Must return TRUE if the received user data is valid.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-data  (-> request :params)
  ;         user-id    (-> request :session :user-id)]
  ;        (update-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                      :update-user-account-f        #(my-database/update-user-account!                user-id user-data)
  ;                                      :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                      :user-data-valid-f            #(my-validator/user-data-valid?                   user-data)
  ;                                      :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                      :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :performed-request/user-account-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-account-updated
  ;   (The server has been successfully updated the user account),
  ;   :server-error/unable-to-update-user-account
  ;   (The server cannot update the user account),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   update-user-account-f
                   user-authenticated-f
                   user-data-valid-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address           :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent           :status 400}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated       :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists            :status 403}
             (not (user-data-valid-f))                             {:body :forbidden-request/invalid-user-data-received :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded   :status 429}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed  :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed :status 520}
             (not (update-user-account-f))                         {:body :server-error/unable-to-update-user-account   :status 500}
             :user-account-updated                                 {:body :performed-request/user-account-updated       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-authenticated
  ; @description
  ; Security protocol function for verifying a security code sent via email or SMS to an authenticated (logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-ip-address-matches-f (function)
  ;   Must return TRUE if the received security code has been required from the same IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         security-code (-> request :params :security-code)
  ;         user-id       (-> request :session :user-id)]
  ;        (verify-security-code-authenticated request {:client-rate-limit-exceeded-f       #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                                     :security-code-correct-f            #(my-database/security-code-matches?                              user-id security-code)
  ;                                                     :security-code-expired-f            #(my-database/security-code-expired?                              user-id)
  ;                                                     :security-code-ip-address-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                                     :security-code-sent-f               #(my-database/security-code-sent?                                 user-id)
  ;                                                     :security-code-valid-f              #(my-validator/security-code-valid?                               security-code)
  ;                                                     :user-authenticated-f               #(my-validator/request-has-valid-session?                         request)
  ;                                                     :user-exists-f                      #(my-database/user-id-exists?                                     user-id)
  ;                                                     :user-rate-limit-exceeded-f         #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/correct-security-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/security-code-ip-address-not-matches
  ;   (The received security code has been required from another IP address),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/correct-security-code-received
  ;   (Correct security code has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   security-code-ip-address-matches-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                     :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                     :status 400}
             (not (security-code-valid-f))                         {:body :forbidden-request/invalid-security-code-received       :status 403}
             (not (security-code-sent-f))                          {:body :forbidden-request/no-security-code-sent-in-timeframe   :status 403}
             (not (security-code-ip-address-matches-f))            {:body :forbidden-request/security-code-ip-address-not-matches :status 403}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated                 :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists                      :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (not (security-code-correct-f))                       {:body :unauthorized-request/incorrect-security-code-received  :status 401}
             (boolean (security-code-expired-f))                   {:body :unauthorized-request/expired-security-code-received    :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed            :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed           :status 520}
             :security-code-verified                               {:body :performed-request/correct-security-code-received       :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-unauthenticated
  ; @description
  ; Security protocol function for verifying a security code sent via email or SMS to an unauthenticated (not logged-in) user.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ; In case of the 'provide-session-f' function is passed, no security check has been failed, and the received security code is correct,
  ; then it applies the 'provide-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :provide-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-expired-f (function)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-ip-address-matches-f (function)
  ;   Must return TRUE if the received security code has been required from the same IP address.
  ;  :security-code-sent-f (function)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)]
  ;        (verify-security-code-unauthenticated request {:client-rate-limit-exceeded-f       #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                                       :provide-session-f                  #(my-session-handler/add-session-to-response                      %)
  ;                                                       :security-code-correct-f            #(my-database/security-code-matches?                              email-address security-code)
  ;                                                       :security-code-expired-f            #(my-database/security-code-expired?                              email-address)
  ;                                                       :security-code-ip-address-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? email-address ip-address)
  ;                                                       :security-code-sent-f               #(my-database/security-code-sent?                                 email-address)
  ;                                                       :security-code-valid-f              #(my-validator/security-code-valid?                               security-code)
  ;                                                       :user-authenticated-f               #(my-validator/request-has-valid-session?                         request)
  ;                                                       :user-contact-registered-f          #(my-database/email-address-registered?                           email-address)
  ;                                                       :user-contact-valid-f               #(my-validator/email-address-valid?                               email-address)
  ;                                                       :user-password-correct-f            #(my-database/user-password-matches?                              user-password)
  ;                                                       :user-password-valid-f              #(my-validator/user-password-valid?                               user-password)
  ;                                                       :user-rate-limit-exceeded-f         #(my-log-service/too-many-attempts-by-email-address?              email-address)})))
  ; =>
  ; {:body :performed-request/correct-security-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/security-code-ip-address-not-matches
  ;   (The received security code has been required from another IP address),
  ;   :forbidden-request/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/correct-security-code-received
  ;   (Correct security code has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   provide-session-f
                   security-code-correct-f
                   security-code-expired-f
                   security-code-ip-address-matches-f
                   security-code-sent-f
                   security-code-valid-f
                   user-authenticated-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]
            :or {provide-session-f return}}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                     :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                     :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received        :status 403}
             (not (user-password-valid-f))                         {:body :forbidden-request/invalid-user-password-received       :status 403}
             (not (security-code-valid-f))                         {:body :forbidden-request/invalid-security-code-received       :status 403}
             (not (security-code-sent-f))                          {:body :forbidden-request/no-security-code-sent-in-timeframe   :status 403}
             (not (security-code-ip-address-matches-f))            {:body :forbidden-request/security-code-ip-address-not-matches :status 403}
             (not (user-contact-registered-f))                     {:body :forbidden-request/unregistered-user-contact-received   :status 403}
             (boolean (user-authenticated-f))                      {:body :forbidden-request/user-authenticated                   :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded           :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded             :status 429}
             (not (user-password-correct-f))                       {:body :unauthorized-request/incorrect-user-password-received  :status 401}
             (not (security-code-correct-f))                       {:body :unauthorized-request/incorrect-security-code-received  :status 401}
             (boolean (security-code-expired-f))                   {:body :unauthorized-request/expired-security-code-received    :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed            :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed           :status 520}
             :security-code-verified                               (provide-session-f {:body :performed-request/correct-security-code-received :status 200}))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-password
  ; @description
  ; Security protocol function for verifying a user password and optionally sending an MFA security code.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ; In case of the 'provide-session-f' function is passed, the 'send-security-code-f' function is NOT passed, no security check has
  ; been failed, and the received user password is correct, then it applies the 'provide-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security stage that if returns false, the protocol function returns an error response.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :provide-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;  :send-security-code-f (function)(opt)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-contact-registered-f (function)
  ;   Must return TRUE if the received email address / phone number is registered.
  ;  :user-contact-valid-f (function)
  ;   Must return TRUE if the received email address / phone number is valid.
  ;  :user-contact-verified-f (function)
  ;   Must return TRUE if the received email address / phone number is verified.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)
  ;         user-password (-> request :params :password)]
  ;        (verify-user-password request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                       :provide-session-f            #(my-session-handler/add-session-to-response         %)
  ;                                       :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                       :user-authenticated-f         #(my-validator/request-has-valid-session?            request)
  ;                                       :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
  ;                                       :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
  ;                                       :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
  ;                                       :user-password-correct-f      #(my-database/user-password-matches?                 user-password)
  ;                                       :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                       :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid email address / phone number has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/unregistered-user-contact-received
  ;   (Unregistered email address / phone number has been received),
  ;   :forbidden-request/unverified-user-contact-received
  ;   (Unverified email address / phone number has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/correct-user-password-received
  ;   (Correct user password has been received),
  ;   :performed-request/security-code-sent
  ;   (The server has been successfully sent the security code email / SMS to the user),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   provide-session-f
                   send-security-code-f
                   user-authenticated-f
                   user-contact-registered-f
                   user-contact-valid-f
                   user-contact-verified-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]
            :or {provide-session-f return}}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                    :status 400}
             (not (user-contact-valid-f))                          {:body :forbidden-request/invalid-user-contact-received       :status 403}
             (not (user-password-valid-f))                         {:body :forbidden-request/invalid-user-password-received      :status 403}
             (not (user-contact-registered-f))                     {:body :forbidden-request/unregistered-user-contact-received  :status 403}
             (not (user-contact-verified-f))                       {:body :forbidden-request/unverified-user-contact-received    :status 403}
             (boolean (user-authenticated-f))                      {:body :forbidden-request/user-authenticated                  :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (not (user-password-correct-f))                       {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed           :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed          :status 520}
             (not send-security-code-f)                            (provide-session-f {:body :performed-request/correct-user-password-received :status 200})
             (not (send-security-code-f))                          {:body :server-error/unable-to-send-security-code :status 500}
             :security-code-sent                                   {:body :performed-request/security-code-sent      :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-pin-code
  ; @description
  ; Security protocol function for verifying a user PIN code.
  ; Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-check-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :user-authenticated-f (function)
  ;   Must return TRUE the request contains an authenticated / logged in user session.
  ;  :user-exists-f (function)
  ;   Must return TRUE the user exists.
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
  ;   (let [ip-address    (-> request :remote-addr)
  ;         user-pin-code (-> request :params :pin-code)
  ;         user-id       (-> request :session :user-id)]
  ;        (verify-user-pin-code request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                       :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                       :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                       :user-pin-code-correct-f      #(my-database/user-pin-code-matches?              user-pin-code)
  ;                                       :user-pin-code-valid-f        #(my-validator/user-pin-code-valid?               user-pin-code)
  ;                                       :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :performed-request/correct-user-pin-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-pin-code-received
  ;   (Invalid user PIN code has been received),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/correct-user-pin-code-received
  ;   (Correct user PIN code has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions has been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions has been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-user-pin-code-received
  ;   (Incorrect user PIN code has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value)
  ;   :unknown-error/additional-check-stage-failed
  ;   (The additional check function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-check-f
                   client-rate-limit-exceeded-f
                   user-authenticated-f
                   user-exists-f
                   user-pin-code-correct-f
                   user-pin-code-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))            {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))            {:body :invalid-request/invalid-user-agent                    :status 400}
             (not (user-pin-code-valid-f))                         {:body :forbidden-request/invalid-user-pin-code-received      :status 403}
             (not (user-authenticated-f))                          {:body :forbidden-request/user-unauthenticated                :status 403}
             (not (user-exists-f))                                 {:body :forbidden-request/user-not-exists                     :status 403}
             (boolean (client-rate-limit-exceeded-f))              {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (boolean (user-rate-limit-exceeded-f))                {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (not (user-pin-code-correct-f))                       {:body :unauthorized-request/incorrect-user-pin-code-received :status 401}
             (and additional-check-f  (not (additional-check-f)))  {:body :unknown-error/additional-check-stage-failed           :status 520}
             (and additional-action-f (not (additional-action-f))) {:body :unknown-error/additional-action-stage-failed          :status 520}
             :user-pin-code-verified                               {:body :performed-request/correct-user-pin-code-received      :status 200})))

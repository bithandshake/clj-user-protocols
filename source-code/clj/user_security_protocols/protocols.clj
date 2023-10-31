
(ns user-security-protocols.protocols
    (:require [audit.api :as audit]
              [http.api  :as http]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn check-user-identifier
  ; @description
  ; - Security protocol function for checking a user identifier (email address / phone number / username) (for authenticated / unauthenticated users)
  ;   whether it is registered and/or verified.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :user-identifier-registered-f (function)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-identifier-verified-f (function)(opt)
  ;   Must return TRUE if the received user identifier (if contact: email address / phone number) is verified.
  ;  :user-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (check-user-identifier {...} {...})
  ;
  ; @example
  ; (check-user-identifier {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address    (-> request :remote-addr)
  ;         email-address (-> request :params :email-address)]
  ;        (check-user-identifier request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
  ;                                        :user-identifier-registered-f #(my-database/email-address-registered?              email-address)
  ;                                        :user-identifier-valid-f      #(my-validator/email-address-valid?                  email-address)
  ;                                        :user-identifier-verified-f   #(my-database/email-address-verified?                email-address)
  ;                                        :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/user-identifier-verified :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/registered-user-identifier-received
  ;   (Registered user identifier (email address / phone number / username) has been received),
  ;   :performed-request/unregistered-user-identifier-received
  ;   (Unregistered user identifier (email address / phone number / username) has been received),
  ;   :performed-request/unverified-user-identifier-received
  ;   (Registered but unverified user identifier (if contact: email address / phone number) has been received),
  ;   :performed-request/verified-user-identifier-received
  ;   (Registered and verified user identifier (email address / phone number / username) has been received),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-identifier-verified-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address                 :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent                 :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded       :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded         :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                :status 403}
             (and user-identifier-valid-f      (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed     :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed       :status 520}
             ; After every provided security function has been passed, it checks whether the received user identifier (email address / phone number / username)
             ; is registered / unregistered and checks whether it is verified / unverified (if the 'user-identifier-verified-f' function is passed).
             (not (user-identifier-registered-f)) {:body :performed-request/unregistered-user-identifier-received :status 200}
             (not user-identifier-verified-f)     {:body :performed-request/registered-user-identifier-received   :status 200}
             (not (user-identifier-verified-f))   {:body :performed-request/unverified-user-identifier-received   :status 200}
             :verified-user-identifier-received   {:body :performed-request/verified-user-identifier-received     :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn create-user-account
  ; @description
  ; - Security protocol function for creating a user account that is identified by a user identifier (email address / phone number / username)
  ;   and protected by a password.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - In case of the 'send-security-code-f' function is passed, no security check has been failed, and the user account is successfully created,
  ;   it applies the 'send-security-code-f' (it's a common scenario when user account creating followed by login code verification).
  ; - In case of the 'provide-user-session-f' function is passed, the 'send-security-code-f' function is NOT passed, no security check has
  ;   been failed, and the user account is successfully created, it applies the 'provide-user-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :create-user-f (function)
  ;   Side-effect function for creating the user account, applied after and if every security check passed.
  ;   Must return TRUE if the user account has been successfully created.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :provide-user-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;   Must return NIL in case of any error.
  ;  :send-security-code-f (function)(opt)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :send-welcome-message-f (function)(opt)
  ;   Optional side-effect function for sending a welcome message to the user, applied after and if every security check passed.
  ;   Must return TRUE if the welcome email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-data-valid-f (function)(opt)
  ;   Must return TRUE if the received user data is valid.
  ;  :user-identifier-registered-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;                                      :provide-user-session-f       #(my-session-handler/add-session-to-response         %)
  ;                                      :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                      :send-welcome-message-f       #(my-email-service/send-welcome-email!               email-address)
  ;                                      :user-authenticated-f         #(my-validator/request-has-valid-session-valid?      request)
  ;                                      :user-data-valid-f            #(my-validator/user-data-valid?                      user-data)
  ;                                      :user-identifier-registered-f #(my-database/email-address-registered?              email-address)
  ;                                      :user-identifier-valid-f      #(my-validator/email-address-valid?                  email-address)
  ;                                      :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                      :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/user-account-created :status 201}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/registered-user-identifier-received
  ;   (Registered user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-account-created
  ;   (The server has been successfully created the user account),
  ;   :performed-request/user-session-provided
  ;   (The server has been successfully provided a user session to the HTTP response),
  ;   :server-error/unable-to-create-user-account
  ;   (The server cannot create the user account),
  ;   :server-error/unable-to-provide-user-session
  ;   (The server cannot provide the user session to the HTTP response),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :server-error/unable-to-send-welcome-message
  ;   (The server cannot send the welcome email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   201, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   create-user-account-f
                   permission-granted-f
                   provide-user-session-f
                   send-security-code-f
                   send-welcome-message-f
                   user-authenticated-f
                   user-data-valid-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent                    :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                   :status 403}
             (and user-authenticated-f         (boolean (user-authenticated-f)))         {:body :forbidden-request/user-authenticated                  :status 403}
             (and user-identifier-valid-f      (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received    :status 403}
             (and user-password-valid-f        (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received      :status 403}
             (and user-data-valid-f            (not (user-data-valid-f)))                {:body :forbidden-request/invalid-user-data-received          :status 403}
             (and user-identifier-registered-f (boolean (user-identifier-registered-f))) {:body :forbidden-request/registered-user-identifier-received :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed        :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed          :status 520}
             (and send-welcome-message-f       (not (send-welcome-message-f)))           {:body :server-error/unable-to-send-welcome-message           :status 500}
             ; After every provided security function has been passed, it creates the user account and sends a security code (if the 'send-security-code-f' function is passed)
             ; or provide a user session in the HTTP response (if the 'provide-user-session-f' function is passed).
             (not (create-user-account-f))                           {:body :server-error/unable-to-create-user-account :status 500}
             (and send-security-code-f (not (send-security-code-f))) {:body :server-error/unable-to-send-security-code  :status 500}
             (and send-security-code-f)                              {:body :performed-request/security-code-sent       :status 201}
             (not provide-user-session-f)                            {:body :performed-request/user-account-created     :status 201}
             :providing-user-session                                 (if-let [response (provide-user-session-f {:body :performed-request/ready-to-provide-user-session :status 201})]
                                                                             (->> {:body :performed-request/user-session-provided     :status 201} (merge response))
                                                                             (->  {:body :server-error/unable-to-provide-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn drop-user-session
  ; @description
  ; - Security protocol function for dropping a user session.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response indicating the result of the checks.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :drop-user-session-f (function)
  ;   Must take the response as parameter, and remove the user session from it.
  ;   Must return NIL in case of any error.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;                                    :drop-user-session-f          #(assoc % :session {})
  ;                                    :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                    :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                    :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id}))
  ; =>
  ; {:body :performed-request/user-session-dropped :status 200 :session {}}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
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
  ;   :server-error/unable-to-drop-user-session
  ;   (The server cannot remove the user session from the HTTP response),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   drop-user-session-f
                   permission-granted-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
             (and user-authenticated-f         (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated         :status 403}
             (and user-exists-f                (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists              :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
             ; After every provided security function has been passed, it removes the user session from the HTTP response.
             :dropping-user-session (if-let [response (drop-user-session-f {:body :performed-request/ready-to-drop-user-session :status 200})]
                                            (->> {:body :performed-request/user-session-dropped   :status 200} (merge response))
                                            (->  {:body :server-error/unable-to-drop-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn recover-user-password
  ; @description
  ; - Security protocol function for user password recovering (for authenticated users) with optional security code verification.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - In case of the 'provide-user-session-f' function is passed, no security check has been failed, and the received security code is correct,
  ;   it applies the 'provide-user-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :fresh-password-valid-f (function)
  ;   Must return TRUE if the received fresh password is valid.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :provide-user-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;   Must return NIL in case of any error.
  ;  :recover-user-password-f (function)
  ;   Side-effect function for recovering the user's password, applied after and if every security check passed.
  ;   Must return TRUE if the user's password has been successfully recovered.
  ;  :security-code-correct-f (function)(opt)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-identifier-registered-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-identifier-verified-f (function)(opt)
  ;   Must return TRUE if the received user identifier (if contact: email address / phone number) is verified.
  ;  :user-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (recover-user-password {...} {...})
  ;
  ; @example
  ; (recover-user-password {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address     (-> request :remote-addr)
  ;         email-address  (-> request :params :email-address)
  ;         fresh-password (-> request :params :fresh-password)
  ;         security-code  (-> request :params :security-code)
  ;         user-id        (my-database/get-user-id-by-email-address email-address)]
  ;        (recover-user-password request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                        :fresh-password-valid-f         #(my-validator/user-password-valid?                               fresh-password)
  ;                                        :provide-user-session-f         #(my-session-handler/add-session-to-response                      %)
  ;                                        :recover-user-password-f        #(my-database/recover-user-password!                              user-id fresh-password)
  ;                                        :security-code-correct-f        #(my-database/security-code-matches?                              user-id security-code)
  ;                                        :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                        :security-code-expired-f        #(my-database/security-code-expired?                              user-id)
  ;                                        :security-code-sent-f           #(my-database/security-code-sent?                                 user-id)
  ;                                        :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                        :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                        :user-identifier-registered-f   #(my-database/email-address-registered?                           email-address)
  ;                                        :user-identifier-valid-f        #(my-validator/email-address-valid?                               email-address)
  ;                                        :user-identifier-verified-f     #(my-database/email-address-verified?                             email-address)
  ;                                        :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-password-recovered :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :forbidden-request/invalid-fresh-password-received
  ;   (Invalid fresh password has been received),
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
  ;   :forbidden-request/unregistered-user-identifier-received
  ;   (Unregistered user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/unverified-user-identifier-received
  ;   (Unverified user identifier (if contact: email address / phone number) has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :performed-request/user-password-recovered
  ;   (The server has been successfully recovered the user's password),
  ;   :performed-request/user-session-provided
  ;   (The server has been successfully provided a user session to the HTTP response),
  ;   :server-error/unable-to-provide-user-session
  ;   (The server cannot provide the user session to the HTTP response),
  ;   :server-error/unable-to-recover-user-password
  ;   (The server cannot recover the user's password),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   fresh-password-valid-f
                   permission-granted-f
                   provide-user-session-f
                   recover-user-password-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   user-authenticated-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-identifier-verified-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                      :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                      :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded            :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded              :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                     :status 403}
             (and user-authenticated-f           (boolean (user-authenticated-f)))         {:body :forbidden-request/user-authenticated                    :status 403}
             (and fresh-password-valid-f         (not (fresh-password-valid-f)))           {:body :forbidden-request/invalid-fresh-password-received       :status 403}
             (and user-identifier-valid-f        (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received      :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received        :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe    :status 403}
             (and user-identifier-registered-f   (not (user-identifier-registered-f)))     {:body :forbidden-request/unregistered-user-identifier-received :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches      :status 403}
             (and user-identifier-verified-f     (not (user-identifier-verified-f)))       {:body :forbidden-request/unverified-user-identifier-received   :status 403}
             (and security-code-correct-f        (not (security-code-correct-f)))          {:body :unauthorized-request/incorrect-security-code-received   :status 401}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received     :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed          :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed            :status 520}
             ; After every provided security function has been passed, it recovers the user password and provides a user session in the HTTP response (if the 'provide-user-session-f'
             ; function is passed).
             (not (recover-user-password-f)) {:body :server-error/unable-to-recover-user-password :status 500}
             (not provide-user-session-f)    {:body :performed-request/user-password-recovered    :status 200}
             :providing-user-session         (if-let [response (provide-user-session-f {:body :performed-request/ready-to-provide-user-session :status 200})]
                                                     (->> {:body :performed-request/user-session-provided     :status 200} (merge response))
                                                     (->  {:body :server-error/unable-to-provide-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn remove-user-account
  ; @description
  ; - Security protocol function for user account removal (for authenticated users) with optional user password and/or security code verification.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :drop-user-session-f (function)(opt)
  ;   Must take the response as parameter, and remove the user session from it.
  ;   Must return NIL in case of any error.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :remove-user-account-f (function)
  ;   Side-effect function for removing the user account, applied after and if every security check passed.
  ;   Must return TRUE if the user account has been successfully removed.
  ;  :security-code-correct-f (function)(opt)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :send-goodbye-message-f (function)(opt)
  ;   Optional side-effect function for sending a goodbye message to the user, applied after and if every security check passed.
  ;   Must return TRUE if the goodbye email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password is correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;        (remove-user-account request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                      :drop-user-session-f            #(assoc % :session {})
  ;                                      :remove-user-account-f          #(my-database/remove-user-account!                                user-id)
  ;                                      :security-code-correct-f        #(my-database/security-code-matches?                              user-id security-code)
  ;                                      :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                      :security-code-expired-f        #(my-database/security-code-expired?                              user-id)
  ;                                      :security-code-sent-f           #(my-database/security-code-sent?                                 user-id)
  ;                                      :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                      :send-goodbye-message-f         #(my-email-service/send-goodbye-email!                            user-id)
  ;                                      :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                      :user-exists-f                  #(my-database/user-id-exists?                                     user-id)
  ;                                      :user-password-correct-f        #(my-database/user-password-matches?                              user-password)
  ;                                      :user-password-valid-f          #(my-validator/user-password-valid?                               user-password)
  ;                                      :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-account-removed :status 200 :session {}}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
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
  ;   :performed-request/user-session-dropped
  ;   (The server has been successfully removed the user account and the user session from the HTTP response),
  ;   :server-error/unable-to-drop-user-session
  ;   (The server cannot remove the user session from the HTTP response),
  ;   :server-error/unable-to-remove-user-account
  ;   (The server cannot remove the user account),
  ;   :server-error/unable-to-send-goodbye-message
  ;   (The server cannot send the goodbye email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   drop-user-session-f
                   permission-granted-f
                   remove-user-account-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   send-goodbye-message-f
                   user-authenticated-f
                   user-exists-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                    :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                   :status 403}
             (and user-authenticated-f           (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated                :status 403}
             (and user-exists-f                  (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                     :status 403}
             (and user-password-valid-f          (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received      :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received      :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe  :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches    :status 403}
             (and user-password-correct-f        (not (user-password-correct-f)))          {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and security-code-correct-f        (not (security-code-correct-f)))          {:body :unauthorized-request/incorrect-security-code-received :status 401}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received   :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed        :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed          :status 520}
             (and send-goodbye-message-f         (not (send-goodbye-message-f)))           {:body :server-error/unable-to-send-goodbye-message           :status 500}
             ; After every provided security function has been passed, it removes the user account and removes the user session from the HTTP response (if the 'drop-user-session-f'
             ; function is passed).
             (not (remove-user-account-f)) {:body :server-error/unable-to-remove-user-account :status 500}
             (not drop-user-session-f)     {:body :performed-request/user-account-removed     :status 200}
             :dropping-user-session        (if-let [response (drop-user-session-f {:body :performed-request/ready-to-drop-user-session :status 200})]
                                                   (->> {:body :performed-request/user-session-dropped   :status 200} (merge response))
                                                   (->  {:body :server-error/unable-to-drop-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-authenticated
  ; @description
  ; - Security protocol function for security code sending via email / SMS (for authenticated users).
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :send-security-code-f (function)
  ;   Side-effect function for sending the security code to the user, applied after and if every security check passed.
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
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
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   send-security-code-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
             (and user-authenticated-f         (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated         :status 403}
             (and user-exists-f                (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists              :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
             ; After every provided security function has been passed, it sends a security code to the user.
             (not (send-security-code-f)) {:body :server-error/unable-to-send-security-code :status 500}
             :security-code-sent          {:body :performed-request/security-code-sent      :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn send-security-code-unauthenticated
  ; @description
  ; - Security protocol function for security code sending via email / SMS (for unauthenticated users).
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :send-security-code-f (function)
  ;   Side-effect function for sending the security code to the user, applied after and if every security check passed.
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-identifier-registered-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-identifier-verified-f (function)(opt)
  ;   Must return TRUE if the received user identifier (if contact: email address / phone number) is verified.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;                                                     :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                                     :user-authenticated-f         #(my-validator/request-has-valid-session?            request)
  ;                                                     :user-identifier-registered-f #(my-database/email-address-registered?              email-address)
  ;                                                     :user-identifier-valid-f      #(my-validator/email-address-valid?                  email-address)
  ;                                                     :user-identifier-verified-f   #(my-database/email-address-verified?                email-address)
  ;                                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/unregistered-user-identifier-received
  ;   (Unregistered user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/unverified-user-identifier-received
  ;   (Unverified user identifier (if contact: email address / phone number) has been received),
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
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   send-security-code-f
                   user-authenticated-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-identifier-verified-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address                      :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent                      :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded            :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded              :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                     :status 403}
             (and user-authenticated-f         (boolean (user-authenticated-f)))         {:body :forbidden-request/user-authenticated                    :status 403}
             (and user-identifier-valid-f      (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received      :status 403}
             (and user-identifier-registered-f (not (user-identifier-registered-f)))     {:body :forbidden-request/unregistered-user-identifier-received :status 403}
             (and user-identifier-verified-f   (not (user-identifier-verified-f)))       {:body :forbidden-request/unverified-user-identifier-received   :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed          :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed            :status 520}
             ; After every provided security function has been passed, it sends a security code to the user.
             (not (send-security-code-f)) {:body :server-error/unable-to-send-security-code :status 500}
             :security-code-sent          {:body :performed-request/security-code-sent      :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-contact
  ; @description
  ; - Security protocol function for user contact (email address / phone number) update (for authenticated users) with optional user password
  ;   and/or security code verification.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :security-code-correct-f (function)(opt)
  ;   Must return TRUE if the received security code is correct.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :update-user-contact-f (function)
  ;   Side-effect function for updating the user contact, applied after and if every security check passed.
  ;   Must return TRUE if the user contact (email address / phone number) has been successfully updated.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-contact-registered-f (function)(opt)
  ;   Must return TRUE if the received user contact (email address / phone number) is registered.
  ;  :user-contact-valid-f (function)(opt)
  ;   Must return TRUE if the received user contact (email address / phone number) is valid.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password is correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;        (update-user-contact request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                      :security-code-correct-f        #(my-database/security-code-matches?                              user-id security-code)
  ;                                      :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                      :security-code-expired-f        #(my-database/security-code-expired?                              user-id)
  ;                                      :security-code-sent-f           #(my-database/security-code-sent?                                 user-id)
  ;                                      :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                      :update-user-contact-f          #(my-database/update-user-email-address!                          user-id email-address)
  ;                                      :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                      :user-contact-registered-f      #(my-database/email-address-registered?                           email-address)
  ;                                      :user-contact-valid-f           #(my-validator/email-address-valid?                               email-address)
  ;                                      :user-exists-f                  #(my-database/user-id-exists?                                     user-id)
  ;                                      :user-password-correct-f        #(my-database/user-password-matches?                              user-password)
  ;                                      :user-password-valid-f          #(my-validator/user-password-valid?                               user-password)
  ;                                      :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-contact-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-contact-received
  ;   (Invalid user contact (email address / phone number) has been received),
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/registered-user-contact-received
  ;   (Registered user contact (email address / phone number) has been received),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
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
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
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
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                    :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                   :status 403}
             (and user-authenticated-f           (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated                :status 403}
             (and user-exists-f                  (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                     :status 403}
             (and user-password-valid-f          (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received      :status 403}
             (and user-contact-valid-f           (not (user-contact-valid-f)))             {:body :forbidden-request/invalid-user-contact-received       :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received      :status 403}
             (and user-contact-registered-f      (boolean (user-contact-registered-f)))    {:body :forbidden-request/registered-user-contact-received    :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe  :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches    :status 403}
             (and user-password-correct-f        (not (user-password-correct-f)))          {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and security-code-correct-f        (not (security-code-correct-f)))          {:body :unauthorized-request/incorrect-security-code-received :status 401}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received   :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed        :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed          :status 520}
             ; After every provided security function has been passed, it updates the user's contact (email address / phone number).
             (not (update-user-contact-f)) {:body :server-error/unable-to-update-user-contact :status 500}
             :user-contact-updated         {:body :performed-request/user-contact-updated     :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-data
  ; @description
  ; - Security protocol function for user data update (for authenticated users).
  ; - For updating user contact (email address / phone number), username, or user password use the specific functions!
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :update-user-data-f (function)
  ;   Side-effect function for updating the user data, applied after and if every security check passed.
  ;   Must return TRUE if the user data has been successfully updated.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-data-valid-f (function)(opt)
  ;   Must return TRUE if the received user data is valid.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (update-user-data {...} {...})
  ;
  ; @example
  ; (update-user-data {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-data  (-> request :params)
  ;         user-id    (-> request :session :user-id)]
  ;        (update-user-data request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                   :update-user-data-f           #(my-database/update-user-data!                   user-id user-data)
  ;                                   :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                   :user-data-valid-f            #(my-validator/user-data-valid?                   user-data)
  ;                                   :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                   :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :performed-request/user-data-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-data-received
  ;   (Invalid user data has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-data-updated
  ;   (The server has been successfully updated the user data),
  ;   :server-error/unable-to-update-user-data
  ;   (The server cannot update the user data),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   update-user-data-f
                   user-authenticated-f
                   user-data-valid-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
             (and user-authenticated-f         (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated         :status 403}
             (and user-exists-f                (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists              :status 403}
             (and user-data-valid-f            (not (user-data-valid-f)))                {:body :forbidden-request/invalid-user-data-received   :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
             ; After every provided security function has been passed, it updates the user's data.
             (not (update-user-data-f)) {:body :server-error/unable-to-update-user-data :status 500}
             :user-account-updated      {:body :performed-request/user-data-updated     :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-user-password
  ; @description
  ; - Security protocol function for user account password update (for authenticated users) with optional user password and/or security code verification.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :fresh-password-valid-f (function)(opt)
  ;   Must return TRUE if the received fresh password is valid.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :security-code-correct-f (function)(opt)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :update-user-password-f (function)
  ;   Side-effect function for updating the user's password, applied after and if every security check passed.
  ;   Must return TRUE if the user's password has been successfully updated.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password is correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (update-user-password {...} {...})
  ;
  ; @example
  ; (update-user-password {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address     (-> request :remote-addr)
  ;         user-password  (-> request :params :password)
  ;         fresh-password (-> request :params :fresh-password)
  ;         security-code  (-> request :params :security-code)
  ;         user-id        (-> request :session :user-id)]
  ;        (update-user-password request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                       :fresh-password-valid-f         #(my-validator/user-password-valid?                               fresh-password)
  ;                                       :security-code-correct-f        #(my-database/security-code-matches?                              user-id security-code)
  ;                                       :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                       :security-code-expired-f        #(my-database/security-code-expired?                              user-id)
  ;                                       :security-code-sent-f           #(my-database/security-code-sent?                                 user-id)
  ;                                       :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                       :update-user-password-f         #(my-database/update-user-password!                               user-id fresh-password)
  ;                                       :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                       :user-exists-f                  #(my-database/user-id-exists?                                     user-id)
  ;                                       :user-password-correct-f        #(my-database/user-password-matches?                              user-password)
  ;                                       :user-password-valid-f          #(my-validator/user-password-valid?                               user-password)
  ;                                       :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/user-password-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-fresh-password-received
  ;   (Invalid fresh password has been received),
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/user-password-updated
  ;   (The server has been successfully updated the user's password),
  ;   :server-error/unable-to-update-user-password
  ;   (The server cannot update the user's password),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   fresh-password-valid-f
                   permission-granted-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   update-user-password-f
                   user-authenticated-f
                   user-exists-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                    :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                   :status 403}
             (and user-authenticated-f           (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated                :status 403}
             (and user-exists-f                  (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                     :status 403}
             (and fresh-password-valid-f         (not (fresh-password-valid-f)))           {:body :forbidden-request/invalid-fresh-password-received     :status 403}
             (and user-password-valid-f          (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received      :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received      :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe  :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches    :status 403}
             (and user-password-correct-f        (not (user-password-correct-f)))          {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and security-code-correct-f        (not (security-code-correct-f)))          {:body :unauthorized-request/incorrect-security-code-received :status 401}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received   :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed        :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed          :status 520}
             ; After every provided security function has been passed, it updates the user's password.
             (not (update-user-password-f)) {:body :server-error/unable-to-update-user-password :status 500}
             :user-password-updated         {:body :performed-request/user-password-updated     :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn update-username
  ; @description
  ; - Security protocol function for updating a username (for authenticated users) with optional password verification.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :update-username-f (function)
  ;   Side-effect function for updating the username, applied after and if every security check passed.
  ;   Must return TRUE if the username has been successfully updated.
  ;  :username-registered-f (function)(opt)
  ;   Must return TRUE if the received username is registered.
  ;  :username-valid-f (function)(opt)
  ;   Must return TRUE if the received username is valid.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password is correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (update-username {...} {...})
  ;
  ; @example
  ; (update-username {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @example
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address    (-> request :remote-addr)
  ;         username      (-> request :params :username)
  ;         user-password (-> request :params :password)
  ;         security-code (-> request :params :security-code)
  ;         user-id       (-> request :session :user-id)]
  ;        (update-username request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                                  :update-username-f            #(my-database/update-user-username!               user-id username)
  ;                                  :username-registered-f        #(my-database/username-registered?                username)
  ;                                  :username-valid-f             #(my-validator/username-valid?                    username)
  ;                                  :user-authenticated-f         #(my-validator/request-has-valid-session?         request)
  ;                                  :user-exists-f                #(my-database/user-id-exists?                     user-id)
  ;                                  :user-password-correct-f      #(my-database/user-password-matches?              user-password)
  ;                                  :user-password-valid-f        #(my-validator/user-password-valid?               user-password)
  ;                                  :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
  ; =>
  ; {:body :performed-request/username-updated :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-username-received
  ;   (Invalid username has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/registered-username-received
  ;   (Registered username has been received),
  ;   :forbidden-request/user-not-exists
  ;   (The user ID does not exist),
  ;   :forbidden-request/user-unauthenticated
  ;   (The user is unauthenticated / not logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/username-updated
  ;   (The server has been successfully updated the username),
  ;   :server-error/unable-to-update-username
  ;   (The server cannot update the username),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   update-username-f
                   username-registered-f
                   username-valid-f
                   user-authenticated-f
                   user-exists-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address                    :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent                    :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded          :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded            :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                   :status 403}
             (and user-authenticated-f         (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated                :status 403}
             (and user-exists-f                (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                     :status 403}
             (and username-valid-f             (not (username-valid-f)))                 {:body :forbidden-request/invalid-username-received           :status 403}
             (and user-password-valid-f        (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received      :status 403}
             (and username-registered-f        (boolean (username-registered-f)))        {:body :forbidden-request/registered-username-received        :status 403}
             (and user-password-correct-f      (not (user-password-correct-f)))          {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed        :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed          :status 520}
             ; After every provided security function has been passed, it updates the user's username.
             (not (update-username-f)) {:body :server-error/unable-to-update-username :status 500}
             :username-updated         {:body :performed-request/username-updated     :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-authenticated
  ; @description
  ; - Security protocol function for verifying a security code (for authenticated users) sent via email / SMS.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;        (verify-security-code-authenticated request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                                     :security-code-correct-f        #(my-database/security-code-matches?                              user-id security-code)
  ;                                                     :security-code-expired-f        #(my-database/security-code-expired?                              user-id)
  ;                                                     :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? user-id ip-address)
  ;                                                     :security-code-sent-f           #(my-database/security-code-sent?                                 user-id)
  ;                                                     :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                                     :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                                     :user-exists-f                  #(my-database/user-id-exists?                                     user-id)
  ;                                                     :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-user-id?                    user-id)})))
  ; =>
  ; {:body :performed-request/correct-security-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
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
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   user-authenticated-f
                   user-exists-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                   :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                   :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded         :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded           :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                  :status 403}
             (and user-authenticated-f           (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated               :status 403}
             (and user-exists-f                  (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                    :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received     :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches   :status 403}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received  :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed       :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed         :status 520}
             ; After every provided security function has been passed, it checks whether the received security code is correct.
             (not (security-code-correct-f)) {:body :unauthorized-request/incorrect-security-code-received :status 401}
             :security-code-verified         {:body :performed-request/correct-security-code-received      :status 200})))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-security-code-unauthenticated
  ; @description
  ; - Security protocol function for verifying a security code (for unauthenticated users) sent via email / SMS.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - In case of the 'provide-user-session-f' function is passed, no security check has been failed, and the received security code is correct,
  ;   it applies the 'provide-user-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :provide-user-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;   Must return NIL in case of any error.
  ;  :security-code-correct-f (function)
  ;   Must return TRUE if the received security code is correct.
  ;  :security-code-device-matches-f (function)(opt)
  ;   Must return TRUE if the received security code has been required from the same device.
  ;  :security-code-expired-f (function)(opt)
  ;   Must return TRUE if the received security code has been expired.
  ;  :security-code-sent-f (function)(opt)
  ;   Must return TRUE if a security code has been sent.
  ;  :security-code-valid-f (function)(opt)
  ;   Must return TRUE if the received security code is valid.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-identifier-registered-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-identifier-verified-f (function)(opt)
  ;   Must return TRUE if the received user identifier (if contact: email address / phone number) is verified.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password is correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;        (verify-security-code-unauthenticated request {:client-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-ip-address?                 ip-address)
  ;                                                       :provide-user-session-f         #(my-session-handler/add-session-to-response                      %)
  ;                                                       :security-code-correct-f        #(my-database/security-code-matches?                              email-address security-code)
  ;                                                       :security-code-device-matches-f #(my-log-service/security-code-required-from-the-same-ip-address? email-address ip-address)
  ;                                                       :security-code-expired-f        #(my-database/security-code-expired?                              email-address)
  ;                                                       :security-code-sent-f           #(my-database/security-code-sent?                                 email-address)
  ;                                                       :security-code-valid-f          #(my-validator/security-code-valid?                               security-code)
  ;                                                       :user-authenticated-f           #(my-validator/request-has-valid-session?                         request)
  ;                                                       :user-identifier-registered-f   #(my-database/email-address-registered?                           email-address)
  ;                                                       :user-identifier-valid-f        #(my-validator/email-address-valid?                               email-address)
  ;                                                       :user-identifier-verified-f     #(my-database/email-address-verified?                             email-address)
  ;                                                       :user-password-correct-f        #(my-database/user-password-matches?                              user-password)
  ;                                                       :user-password-valid-f          #(my-validator/user-password-valid?                               user-password)
  ;                                                       :user-rate-limit-exceeded-f     #(my-log-service/too-many-attempts-by-email-address?              email-address)})))
  ; =>
  ; {:body :performed-request/correct-security-code-received :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-security-code-received
  ;   (Invalid security code has been received),
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/no-security-code-sent-in-timeframe
  ;   (No security code has been sent in a specific timeframe),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/security-code-device-not-matches
  ;   (The received security code has been required from another device),
  ;   :forbidden-request/unregistered-user-identifier-received
  ;   (Unregistered user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/user-authenticated
  ;   (The user is authenticated / logged in),
  ;   :invalid-request/invalid-ip-address
  ;   (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent
  ;   (No valid user agent has been found in the request),
  ;   :performed-request/correct-security-code-received
  ;   (Correct security code has been received),
  ;   :performed-request/user-session-provided
  ;   (The server has been successfully provided a user session to the HTTP response),
  ;   :server-error/unable-to-provide-user-session
  ;   (The server cannot provide the user session to the HTTP response),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/expired-security-code-received
  ;   (Expired security code has been received),
  ;   :unauthorized-request/incorrect-security-code-received
  ;   (Incorrect security code has been received),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   provide-user-session-f
                   security-code-correct-f
                   security-code-device-matches-f
                   security-code-expired-f
                   security-code-sent-f
                   security-code-valid-f
                   user-authenticated-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-identifier-verified-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                    {:body :invalid-request/invalid-ip-address                      :status 400}
             (not (audit/user-agent-valid? user-agent))                                    {:body :invalid-request/invalid-user-agent                      :status 400}
             (and client-rate-limit-exceeded-f   (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded            :status 429}
             (and user-rate-limit-exceeded-f     (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded              :status 429}
             (and permission-granted-f           (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                     :status 403}
             (and user-authenticated-f           (boolean (user-authenticated-f)))         {:body :forbidden-request/user-authenticated                    :status 403}
             (and user-identifier-valid-f        (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received      :status 403}
             (and user-password-valid-f          (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received        :status 403}
             (and security-code-valid-f          (not (security-code-valid-f)))            {:body :forbidden-request/invalid-security-code-received        :status 403}
             (and security-code-sent-f           (not (security-code-sent-f)))             {:body :forbidden-request/no-security-code-sent-in-timeframe    :status 403}
             (and user-identifier-registered-f   (not (user-identifier-registered-f)))     {:body :forbidden-request/unregistered-user-identifier-received :status 403}
             (and security-code-device-matches-f (not (security-code-device-matches-f)))   {:body :forbidden-request/security-code-device-not-matches      :status 403}
             (and user-identifier-verified-f     (not (user-identifier-verified-f)))       {:body :forbidden-request/unverified-user-identifier-received   :status 403}
             (and user-password-correct-f        (not (user-password-correct-f)))          {:body :unauthorized-request/incorrect-user-password-received   :status 401}
             (and security-code-expired-f        (boolean (security-code-expired-f)))      {:body :unauthorized-request/expired-security-code-received     :status 401}
             (and additional-security-f          (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed          :status 520}
             (and additional-action-f            (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed            :status 520}
             ; After every provided security function has been passed, it checks whether the received security code is correct.
             (not (security-code-correct-f)) {:body :unauthorized-request/incorrect-security-code-received :status 401}
             (not provide-user-session-f)    {:body :performed-request/correct-security-code-received      :status 200}
             :providing-user-session         (if-let [response (provide-user-session-f {:body :performed-request/ready-to-provide-user-session :status 200})]
                                                     (->> {:body :performed-request/user-session-provided     :status 200} (merge response))
                                                     (->  {:body :server-error/unable-to-provide-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-password
  ; @description
  ; - Security protocol function for user password verification (for unauthenticated users) and in case of correct user password has been
  ;   received optionally sending an MFA security code / providing a user session.
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - In case of the 'send-security-code-f' function is passed, no security check has been failed, and the received user password is correct,
  ;   it applies the 'send-security-code-f' (it's a common scenario when the user credentials verification is followed by login code verification).
  ; - In case of the 'provide-user-session-f' function is passed, the 'send-security-code-f' function is NOT passed, no security check has
  ;   been failed, and the received user password is correct, it applies the 'provide-user-session-f' function on the HTTP response.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :provide-user-session-f (function)(opt)
  ;   Must take the response as parameter, and associate a user session to it.
  ;   Must return NIL in case of any error.
  ;  :send-security-code-f (function)(opt)
  ;   Must return TRUE if the security code email / SMS has been successfully sent.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-identifier-registered-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is registered.
  ;  :user-identifier-valid-f (function)(opt)
  ;   Must return TRUE if the received user identifier (email address / phone number / username) is valid.
  ;  :user-identifier-verified-f (function)(opt)
  ;   Must return TRUE if the received user identifier (if contact: email address / phone number) is verified.
  ;  :user-password-correct-f (function)(opt)
  ;   Must return TRUE if the received user password are correct.
  ;  :user-password-valid-f (function)(opt)
  ;   Must return TRUE if the received user password is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;                                       :provide-user-session-f       #(my-session-handler/add-session-to-response         %)
  ;                                       :send-security-code-f         #(my-email-service/send-security-code-email!         email-address)
  ;                                       :user-authenticated-f         #(my-validator/request-has-valid-session?            request)
  ;                                       :user-identifier-registered-f #(my-database/email-address-registered?              email-address)
  ;                                       :user-identifier-valid-f      #(my-validator/email-address-valid?                  email-address)
  ;                                       :user-identifier-verified-f   #(my-database/email-address-verified?                email-address)
  ;                                       :user-password-correct-f      #(my-database/user-password-matches?                 user-password)
  ;                                       :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
  ;                                       :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
  ; =>
  ; {:body :performed-request/security-code-sent :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/invalid-user-identifier-received
  ;   (Invalid user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/invalid-user-password-received
  ;   (Invalid user password has been received),
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
  ;   :forbidden-request/unregistered-user-identifier-received
  ;   (Unregistered user identifier (email address / phone number / username) has been received),
  ;   :forbidden-request/unverified-user-identifier-received
  ;   (Unverified user identifier (if contact: email address / phone number) has been received),
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
  ;   :performed-request/user-session-provided
  ;   (The server has been successfully provided a user session to the HTTP response),
  ;   :server-error/unable-to-provide-user-session
  ;   (The server cannot provide the user session to the HTTP response),
  ;   :server-error/unable-to-send-security-code
  ;   (The server cannot send the security code email / SMS to the user),
  ;   :too-many-requests/client-rate-limit-exceeded
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-user-password-received
  ;   (Incorrect user password has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   provide-user-session-f
                   send-security-code-f
                   user-authenticated-f
                   user-identifier-registered-f
                   user-identifier-valid-f
                   user-identifier-verified-f
                   user-password-correct-f
                   user-password-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address                      :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent                      :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded            :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded              :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied                     :status 403}
             (and user-authenticated-f         (boolean (user-authenticated-f)))         {:body :forbidden-request/user-authenticated                    :status 403}
             (and user-identifier-valid-f      (not (user-identifier-valid-f)))          {:body :forbidden-request/invalid-user-identifier-received      :status 403}
             (and user-password-valid-f        (not (user-password-valid-f)))            {:body :forbidden-request/invalid-user-password-received        :status 403}
             (and user-identifier-registered-f (not (user-identifier-registered-f)))     {:body :forbidden-request/unregistered-user-identifier-received :status 403}
             (and user-identifier-verified-f   (not (user-identifier-verified-f)))       {:body :forbidden-request/unverified-user-identifier-received   :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed          :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed            :status 520}
             ; After every provided security function has been passed, it checks whether the received user password is correct and sends a security code to the user
             ; (if the 'send-security-code-f' function is passed) or provides a user session in the HTTP response (if the 'provide-user-session-f' function is passed).
             (not (user-password-correct-f))                         {:body :unauthorized-request/incorrect-user-password-received :status 401}
             (and send-security-code-f (not (send-security-code-f))) {:body :server-error/unable-to-send-security-code             :status 500}
             (and send-security-code-f)                              {:body :performed-request/security-code-sent                  :status 200}
             (not provide-user-session-f)                            {:body :performed-request/correct-user-password-received      :status 200}
             :providing-user-session                                 (if-let [response (provide-user-session-f {:body :performed-request/ready-to-provide-user-session :status 200})]
                                                                             (->> {:body :performed-request/user-session-provided     :status 200} (merge response))
                                                                             (->  {:body :server-error/unable-to-provide-user-session :status 500})))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn verify-user-pin-code
  ; @description
  ; - Security protocol function for user PIN code verification (for authenticated users).
  ; - For performing additional side effects use the 'additional-action-f' function.
  ; - For implementing additional security levels use the 'additional-security-f' function.
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)
  ;   Custom side-effect function that is applied if no security check has been failed.
  ;   Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)
  ;   Custom security function that is applied after the built-in security checks.
  ;   Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt)
  ;   Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :permission-granted-f (function)(opt)
  ;   Must return TRUE if the user has permission to do the action.
  ;  :user-authenticated-f (function)(opt)
  ;   Must return TRUE the user is authenticated / logged in.
  ;  :user-exists-f (function)(opt)
  ;   Must return TRUE the user exists.
  ;  :user-pin-code-correct-f (function)
  ;   Must return TRUE if the received user PIN code is correct.
  ;  :user-pin-code-valid-f (function)(opt)
  ;   Must return TRUE if the received user PIN code is valid.
  ;  :user-rate-limit-exceeded-f (function)(opt)
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
  ;   :forbidden-request/permission-denied
  ;   (The user has no permission to do the action),
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
  ;   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded
  ;   (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unauthorized-request/incorrect-user-pin-code-received
  ;   (Incorrect user PIN code has been received),
  ;   :unknown-error/additional-action-stage-failed
  ;   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed
  ;   (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 401, 403, 429, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   user-authenticated-f
                   user-exists-f
                   user-pin-code-correct-f
                   user-pin-code-valid-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address               :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent               :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded     :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded       :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied              :status 403}
             (and user-authenticated-f         (not (user-authenticated-f)))             {:body :forbidden-request/user-unauthenticated           :status 403}
             (and user-exists-f                (not (user-exists-f)))                    {:body :forbidden-request/user-not-exists                :status 403}
             (and user-pin-code-valid-f        (not (user-pin-code-valid-f)))            {:body :forbidden-request/invalid-user-pin-code-received :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed   :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed     :status 520}
             ; After every provided security function has been passed, it checks whether the received user PIN code is correct.
             (not (user-pin-code-correct-f)) {:body :unauthorized-request/incorrect-user-pin-code-received :status 401}
             :user-pin-code-verified         {:body :performed-request/correct-user-pin-code-received      :status 200})))

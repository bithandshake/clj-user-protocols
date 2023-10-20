
# user-protocols.api Clojure namespace

##### [README](../../../README.md) > [DOCUMENTATION](../../COVER.md) > user-protocols.api

### Index

- [create-user-account](#create-user-account)

- [remove-user-account](#remove-user-account)

- [update-user-account](#update-user-account)

### create-user-account

```
@description
Security protocol function for creating a user account that is identified by an email address or a phone number and protected by a password.
Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
```

```
@param (map) request
@param (map) functions
{:client-rate-limit-exceeded-f (function)
  Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
 :create-user-account-f (function)
  Must return TRUE if the user account has been successfully created.
 :optional-check-f (function)(opt)
  Custom security stage that if returns false, the protocol function returns an error response.
 :send-welcome-message-f (function)
  Must return TRUE if the welcome email / SMS has been successfully sent.
 :user-contact-registered-f (function)
  Must return TRUE if the received email address / phone number is registered.
 :user-contact-valid-f (function)
  Must return TRUE if the received email address / phone number is valid.
 :user-data-valid-f (function)
  Must return TRUE if the received user data is valid.
 :user-logged-in-f (function)
  Must return TRUE the request contains a valid (logged-in) user session.
 :user-password-valid-f (function)
  Must return TRUE if the received user password is valid.
 :user-rate-limit-exceeded-f (function)
  Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
```

```
@usage
(create-user-account {...} {...})
```

```
@example
(create-user-account {...} {...})
=>
{:body :too-many-requests/user-rate-limit-exceeded :status 429}
```

```
@example
(defn my-route
  [request]
  (let [email-address (-> request :params :email-address)
        user-password (-> request :params :password)
        ip-address    (-> request :remote-addr)
        user-data     (-> request :params)
        user-session  (-> request :session)]
       (create-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address?    ip-address)
                                     :create-user-account-f        #(my-database/create-user-account!                   user-data)
                                     :user-contact-registered-f    #(my-database/email-address-registered?              email-address)
                                     :user-contact-valid-f         #(my-validator/email-address-valid?                  email-address)
                                     :user-contact-verified-f      #(my-database/email-address-verified?                email-address)
                                     :user-password-valid-f        #(my-validator/user-password-valid?                  user-password)
                                     :send-welcome-message-f       #(my-email-service/send-welcome-email!               email-address)
                                     :user-data-valid-f            #(my-validator/user-data-valid?                      user-data)
                                     :user-logged-in-f             #(my-validator/user-session-valid?                   user-session)
                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-email-address? email-address)})))
=>
{:body :standard-activity/user-account-created :status 200}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address
  (No IP address has been found in the request),
  :invalid-request/missing-user-agent
  (No user agent has been found in the request),
  :illegal-client-behaviour/invalid-user-contact-received
  (Invalid email address / phone number has been received),
  :illegal-client-behaviour/invalid-user-data-received
  (Invalid user data has been received),
  :illegal-client-behaviour/invalid-user-password-received
  (Invalid user password has been received),
  :illegal-client-behaviour/user-already-logged-in
  (The user has been already logged in and has a valid session),
  :illegal-client-behaviour/registered-user-contact-received
  (Registered email address / phone number has been received),
  :server-error/unable-to-create-user-account
  (The server cannot create the user account),
  :standard-activity/unable-to-send-welcome-message
  (The server cannot send the welcome email / SMS to the user. It's not declared
   as an error because before the contact validation, the given email address /
   phone number might contain typos or might not working),
  :standard-activity/user-account-created
  (The server has been successfully created the user account),
  :too-many-requests/client-rate-limit-exceeded
  (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  :too-many-requests/user-rate-limit-exceeded
  (Too many actions has been attempted by the user in a specific timeframe),
  :unknown-error/optional-check-stage-failed
  (The optional check function returned a false value)
 :status (integer)
  200, 400, 403, 429, 500, 520}
```

<details>
<summary>Source code</summary>

```
(defn create-user-account
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
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [create-user-account]]))

(user-protocols.api/create-user-account ...)
(create-user-account                    ...)
```

</details>

---

### remove-user-account

```
@description
Security protocol function for a user account removal that requires a user password and security code verification.
Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
```

```
@param (map) request
@param (map) functions
{:client-rate-limit-exceeded-f (function)
  Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
 :optional-check-f (function)(opt)
  Custom security stage that if returns false, the protocol function returns an error response.
 :remove-user-account-f (function)
  Must return TRUE if the user account has been successfully removed.
 :security-code-correct-f (function)
  Must return TRUE if the received security code is correct.
 :security-code-expired-f (function)
  Must return TRUE if the received security code has been expired.
 :security-code-required-from-another-ip-address-f (function)
  Must return TRUE if the received security code has been required from another IP address.
 :security-code-sent-f (function)
  Must return TRUE if a security code has been sent.
 :security-code-valid-f (function)
  Must return TRUE if the received security code is valid.
 :send-goodbye-message-f (function)
  Must return TRUE if the goodbye email / SMS has been successfully sent.
 :user-id-exists-f (function)
  Must return TRUE the user ID exists.
 :user-logged-in-f (function)
  Must return TRUE the request contains a valid (logged-in) user session.
 :user-password-correct-f (function)
  Must return TRUE if the received user password matches the stored one.
 :user-password-valid-f (function)
  Must return TRUE if the received user password is valid.
 :user-rate-limit-exceeded-f (function)
  Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
```

```
@usage
(remove-user-account {...} {...})
```

```
@example
(remove-user-account {...} {...})
=>
{:body :too-many-requests/user-rate-limit-exceeded :status 429}
```

```
@example
(defn my-route
  [request]
  (let [user-password (-> request :params :password)
        security-code (-> request :params :security-code)
        ip-address    (-> request :remote-addr)
        user-id       (-> request :session :user-id)
        user-session  (-> request :session)]
       (remove-user-account request {:client-rate-limit-exceeded-f                     #(my-log-service/too-many-attempts-by-ip-address?                ip-address)
                                     :remove-user-account-f                            #(my-database/remove-user-account!                               user-id)
                                     :security-code-correct-f                          #(my-database/security-code-matches?                             user-id security-code)
                                     :security-code-expired-f                          #(my-database/security-code-expired?                             user-id)
                                     :security-code-required-from-another-ip-address-f #(my-log-service/security-code-required-from-another-ip-address? user-id ip-address)
                                     :security-code-sent-f                             #(my-database/security-code-sent?                                user-id)
                                     :security-code-valid-f                            #(my-validator/security-code-valid?                              security-code)
                                     :send-goodbye-message-f                           #(my-email-service/send-goodbye-email!                           user-id)
                                     :user-id-exists-f                                 #(my-database/user-id-exists?                                    user-id)
                                     :user-logged-in-f                                 #(my-validator/user-session-valid?                               user-session)
                                     :user-password-correct-f                          #(my-database/user-password-matches?                             user-password)
                                     :user-password-valid-f                            #(my-validator/user-password-valid?                              user-password)
                                     :user-rate-limit-exceeded-f                       #(my-log-service/too-many-attempts-by-user-id?                   user-id)})))
=>
{:body :standard-activity/user-account-removed :status 200}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address
  (No IP address has been found in the request),
  :invalid-request/missing-user-agent
  (No user agent has been found in the request),
  :illegal-client-behaviour/invalid-security-code-received
  (Invalid security code has been received),
  :illegal-client-behaviour/invalid-user-password-received
  (Invalid user password has been received),
  :illegal-client-behaviour/no-security-code-sent-in-timeframe
  (No security code has been sent in a specific timeframe),
  :illegal-client-behaviour/security-code-required-from-another-ip-address
  (The received security code has been required from another IP address),
  :illegal-client-behaviour/user-id-not-exists
  (The user ID does not exist),
  :illegal-client-behaviour/user-not-logged-in
  (The user is not logged in / unauthenticated),
  :server-error/unable-to-remove-user-account
  (The server cannot remove the user account),
  :server-error/unable-to-send-goodbye-message
  (The server cannot send the goodbye email / SMS to the user),
  :standard-activity/expired-security-code-received
  (Expired security code has been received),
  :standard-activity/incorrect-security-code-received
  (Incorrect security code has been received),
  :standard-activity/incorrect-user-password-received
  (Incorrect user password has been received),
  :standard-activity/user-account-removed
  (The server has been successfully removed the user account),
  :too-many-requests/client-rate-limit-exceeded
  (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  :too-many-requests/user-rate-limit-exceeded
  (Too many actions has been attempted by the user in a specific timeframe),
  :unknown-error/optional-check-stage-failed
  (The optional check function returned a false value)
 :session (map)
  {}
 :status (integer)
  200, 400, 403, 429, 500, 520}
```

<details>
<summary>Source code</summary>

```
(defn remove-user-account
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
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [remove-user-account]]))

(user-protocols.api/remove-user-account ...)
(remove-user-account                    ...)
```

</details>

---

### update-user-account

```
@description
Security protocol function for updating a user account.
Performs various security checks before returns a HTTP response that indicates if any check failured or the action was successful.
```

```
@param (map) request
@param (map) functions
{:client-rate-limit-exceeded-f (function)
  Must return TRUE if the client device or IP address is involved in too many attempts in a specific timeframe.
 :optional-check-f (function)(opt)
  Custom security stage that if returns false, the protocol function returns an error response.
 :update-user-account-f (function)
  Must return TRUE if the user account has been successfully updated.
 :user-data-valid-f (function)
  Must return TRUE if the received user data is valid.
 :user-id-exists-f (function)
  Must return TRUE the user ID exists.
 :user-logged-in-f (function)
  Must return TRUE the request contains a valid (logged-in) user session.
 :user-rate-limit-exceeded-f (function)
  Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
```

```
@usage
(update-user-account {...} {...})
```

```
@example
(update-user-account {...} {...})
=>
{:body :too-many-requests/user-rate-limit-exceeded :status 429}
```

```
@example
(defn my-route
  [request]
  (let [ip-address   (-> request :remote-addr)
        user-data    (-> request :params)
        user-id      (-> request :session :user-id)
        user-session (-> request :session)]
       (update-user-account request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
                                     :update-user-account-f        #(my-database/update-user-account!                user-id user-data)
                                     :user-data-valid-f            #(my-validator/user-data-valid?                   user-data)
                                     :user-id-exists-f             #(my-database/user-id-exists?                     user-id)
                                     :user-logged-in-f             #(my-validator/user-session-valid?                user-session)
                                     :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id?    user-id)})))
=>
{:body :standard-activity/user-account-update :status 200}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address
  (No IP address has been found in the request),
  :invalid-request/missing-user-agent
  (No user agent has been found in the request),
  :illegal-client-behaviour/invalid-user-data-received
  (Invalid user data has been received),
  :illegal-client-behaviour/user-id-not-exists
  (The user ID does not exist),
  :illegal-client-behaviour/user-not-logged-in
  (The user is not logged in / unauthenticated),
  :server-error/unable-to-update-user-account
  (The server cannot update the user account),
  :standard-activity/user-account-updated
  (The server has been successfully updated the user account),
  :too-many-requests/client-rate-limit-exceeded
  (Too many actions has been attempted by the client device or IP address in a specific timeframe),
  :too-many-requests/user-rate-limit-exceeded
  (Too many actions has been attempted by the user in a specific timeframe),
  :unknown-error/optional-check-stage-failed
  (The optional check function returned a false value)
 :status (integer)
  200, 400, 403, 429, 500, 520}
```

<details>
<summary>Source code</summary>

```
(defn update-user-account
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
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [update-user-account]]))

(user-protocols.api/update-user-account ...)
(update-user-account                    ...)
```

</details>

---

This documentation is generated with the [clj-docs-generator](https://github.com/bithandshake/clj-docs-generator) engine.


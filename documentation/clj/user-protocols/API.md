
# user-protocols.api Clojure namespace

##### [README](../../../README.md) > [DOCUMENTATION](../../COVER.md) > user-protocols.api

### Index

- [check-email-address](#check-email-address)

- [check-phone-number](#check-phone-number)

- [create-user-account](#create-user-account)

- [remove-user-account](#remove-user-account)

- [update-email-address](#update-email-address)

- [update-phone-number](#update-phone-number)

### check-email-address

```
@description
HTTP status 400 (invalid request):
- No user agent has been found in the request.
- No IP address has been found in the request.
HTTP status 403 (illegal client behaviour):
- Invalid email address has been received despite the client-side form validation.
HTTP status 429 (too many attempts by the client):
- Too many actions has been attempted with the received email address in a specific timeframe.
- Too many actions has been attempted with the received IP address in a specific timeframe.
HTTP status 520 (unknown error):
- The optional check function returned a false value.
HTTP status 200 (standard activity):
- No user account has been found with the received email address.
- The email address of the found user account has not been verified.
- The email address of the found user account has been verified.
```

```
@param (map) request
@param (map) functions
{:email-address-registered-f (function)
 :email-address-valid-f (function)
 :email-address-verified-f (function)
 :optional-check-f (function)(opt)
 :too-many-attempts-by-email-address-f (function)
 :too-many-attempts-by-ip-address-f (function)}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address,
  :invalid-request/missing-user-agent,
  :illegal-client-behaviour/invalid-email-address-received,
  :too-many-requests/too-many-attempts-by-email-address,
  :too-many-requests/too-many-attempts-ip-address,
  :standard-activity/unregistered-email-address-received,
  :standard-activity/unverified-email-address-received,
  :standard-activity/verified-email-address-received,
  :unknown-error/optional-check-stage-failed
 :status (integer)
  200, 400, 403, 429, 520}
```

<details>
<summary>Source code</summary>

```
(defn check-email-address
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
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [check-email-address]]))

(user-protocols.api/check-email-address ...)
(check-email-address                    ...)
```

</details>

---

### check-phone-number

```
@description
For further information about this function, check the 'README.md' file.
```

```
@param (map) request
@param (map) functions
{:optional-check-f (function)(opt)
 :phone-number-registered-f (function)
 :phone-number-valid-f (function)
 :phone-number-verified-f (function)
 :too-many-attempts-by-phone-number-f (function)
 :too-many-attempts-by-ip-address-f (function)}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address,
  :invalid-request/missing-user-agent,
  :illegal-client-behaviour/invalid-phone-number-received,
  :too-many-requests/too-many-attempts-by-phone-number,
  :too-many-requests/too-many-attempts-ip-address,
  :standard-activity/unregistered-phone-number-received,
  :standard-activity/unverified-phone-number-received,
  :standard-activity/verified-phone-number-received,
  :unknown-error/optional-check-stage-failed
 :status (integer)
  200, 400, 403, 429, 520}
```

<details>
<summary>Source code</summary>

```
(defn check-phone-number
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
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [check-phone-number]]))

(user-protocols.api/check-phone-number ...)
(check-phone-number                    ...)
```

</details>

---

### create-user-account

```
@description
For further information about this function, check the 'README.md' file.
```

```
@param (map) request
@param (map) functions
{:create-user-f (function)
 :email-address-registered-f (function)
 :email-address-valid-f (function)
 :optional-check-f (function)(opt)
 :password-valid-f (function)
 :send-welcome-email-f (function)
 :user-data-valid-f (function)
 :user-logged-in-f (function)
 :too-many-attempts-by-email-address-f (function)
 :too-many-attempts-by-ip-address-f (function)
 :too-many-failure-by-email-address-f (function)}
```

```
@return (map)
{:body (namespaced keyword)
  :invalid-request/missing-ip-address,
  :invalid-request/missing-user-agent,
  :illegal-client-behaviour/invalid-email-address-received,
  :illegal-client-behaviour/invalid-password-received,
  :illegal-client-behaviour/invalid-user-data-received,
  :illegal-client-behaviour/user-already-logged-in,
  :illegal-client-behaviour/email-address-already-registered,
  :server-error/unable-to-create-user-account,
  :too-many-requests/too-many-attempts-by-email-address,
  :too-many-requests/too-many-attempts-ip-address,
  :too-many-requests/too-many-failure-email-address,
  :standard-activity/unable-to-send-welcome-email,
  :standard-activity/user-account-created,
  :unknown-error/optional-check-stage-failed
 :status (integer)
  200, 400, 403, 429, 500, 520}
```

<details>
<summary>Source code</summary>

```
(defn create-user-account
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
@param (map) request
{:session (map)
  {:user-account/id (string)}
 :transit-params (map)
  {:password (string)
   :ruv-code (string)}}
```

```
@return (map)
{:body (keyword)
 :session (map)
 :status (integer)}
```

<details>
<summary>Source code</summary>

```
(defn remove-user-account
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

### update-email-address

```
@param (map) request
{:session (map)
  {:user-account/id (string)}
 :transit-params (map)
  {:email-address (string)
   :password (string)
   :ueav-code (string)}}
```

```
@return (map)
{:body (string)
 :status (integer)}
```

<details>
<summary>Source code</summary>

```
(defn update-email-address
  [request]
  (let [response (update-email-address-f request)]
       (services.log/reg-user-activity! {:action :updating-email-address :request request :response response})
       (http/text-wrap response {:hide-errors? true})))
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [update-email-address]]))

(user-protocols.api/update-email-address ...)
(update-email-address                    ...)
```

</details>

---

### update-phone-number

```
@param (map) request
{:session (map)
  {:user-account/id (string)}
 :transit-params (map)
  {:password (string)
   :phone-number (string)
   :upnv-code (string)}}
```

```
@return (map)
{:body (string)
 :status (integer)}
```

<details>
<summary>Source code</summary>

```
(defn update-phone-number
  [request]
  (let [response (update-phone-number-f request)]
       (services.log/reg-user-activity! {:action :updating-phone-number :request request :response response})
       (http/text-wrap response {:hide-errors? true})))
```

</details>

<details>
<summary>Require</summary>

```
(ns my-namespace (:require [user-protocols.api :refer [update-phone-number]]))

(user-protocols.api/update-phone-number ...)
(update-phone-number                    ...)
```

</details>

---

This documentation is generated with the [clj-docs-generator](https://github.com/bithandshake/clj-docs-generator) engine.


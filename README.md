
# clj-user-protocols

### Overview

The <strong>clj-user-protocols</strong> is a set of user handling and user security
protocols for Clojure projects.

### deps.edn

```
{:deps {bithandshake/clj-user-protocols {:git/url "https://github.com/bithandshake/clj-user-protocols"
                                         :sha     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}
```

### Current version

Check out the latest commit on the [release branch](https://github.com/bithandshake/clj-user-protocols/tree/release).

### Documentation

The <strong>clj-user-protocols</strong> functional documentation is [available here](documentation/COVER.md).

### Changelog

You can track the changes of the <strong>clj-user-protocols</strong> library [here](CHANGES.md).

# Usage

### Index

- [Abbreviations](#abbreviations)

- [In general](#in-general)

- [Possible HTTP responses](#possible-http-responses)

- [The `check-email-address` protocol](#the-check-email-address-protocol)

- [The `check-phone-number` protocol](#the-check-phone-number-protocol)

- [The `create-user-account` protocol](#the-create-user-account-protocol)

### Abbreviations

- `EAS code`:  Email address security code, for user actions that require multi-factor authentication.
- `EAV code`:  Email address verification code, for user email address verification.
- `EANP pair`: Email address and password pair, for email address based login method.
- `PNNP pair`: Phone number and password pair, for phone number based login method.
- `PNS code`:  Phone number security code, for user actions that require multi-factor authentication.
- `PNV code`:  Phone number verification code, for user phone number verification.

### In general

This library is a set of protocol functions that are containing composed security
checks for the most common user account actions. These protocol functions are only
applying the security checks by using working functions that are provided as parameters,
and they are not doing any environmental checking and not making any side effects
on their own!

For example, if your server receives an email address from a client and you want
to check that email address is whether connected to a user account registered in
your system or whether it is already verified by the user, you can use the
`check-email-address` function that takes the working functions as its parameters
and using them to do the security checks that are recommended before checking the
received email address and then will do the actual email address checking.

In the following example, the `my-route` function receives an email address as a
request parameter, and the `check-email-address` function returns a HTTP response
that contains information about whether the email address is registered and also
verified or any security concern has been found around the request.

In order to check the received email address, we will need a few working functions
that are required to be passed to the `check-email-address` function as its parameters.



If no security concern has been found, the `check-email-address` function could
return a HTTP response that looks like any of the followings:

- `{:body :standard-activity/unregistered-email-address-received :status 200}`
- `{:body :standard-activity/unverified-email-address-received   :status 200}`
- `{:body :standard-activity/verified-email-address-received     :status 200}`

If any security concern has been found, the return value could be something like this:

`{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`

The whole list of possible return values of the `check-email-address` function from
this example could be found below.

### The `check-email-address` protocol

The [`user-protocols.api/check-email-address`](documentation/clj/user-protocols/API.md/#check-email-address)
function applies the `check-email-address` protocol.

This protocol function could return with the following HTTP responses:

```
{:invalid-request/missing-ip-address :status 400}
```

- <i>No IP address is found in the request.</i>
- <i>Automatically checked by the actual protocol function.</i>

```
{:invalid-request/missing-user-agent :status 400}
```

- <i>No user agent is found in the request.</i>
- <i>Automatically checked by the actual protocol function.</i>

```
{:illegal-client-behaviour/invalid-email-address-received :status 403}
```

- <i>Invalid email address has been received.</i>
- <i>Checked by the `email-address-valid-f` function.</i>

```
{:too-many-requests/too-many-attempts-by-email-address :status 429}
```

- <i>Too many actions has been attempted in a specific timeframe.</i>
- <i>Checked by the `too-many-attempts-by-email-address-f` function.</i>

```
{:too-many-requests/too-many-attempts-by-ip-address :status 429}
```

- <i>Too many actions has been attempted in a specific timeframe.</i>
- <i>Checked by the `too-many-attempts-by-ip-address-f` function.</i>

```
{:unknown-error/optional-check-stage-failed :status 520}
```

- <i>The optional custom check function returned a false value.</i>
- <i>Checked by the `optional-check-f` function.</i>

```
{:standard-activity/unregistered-email-address-received :status 200}
```

- <i>No user account has been found with the received email address.</i>
- <i>Checked by the `email-address-registered-f` function.</i>

```
{:standard-activity/unverified-email-address-received :status 200}
```

- <i>A user account has been found with the received email address.</i>
- <i>The email address has not been verified yet.</i>
- <i>Checked by the `email-address-verified-f` function.</i>

```
{:standard-activity/verified-email-address-received :status 200}
```

- <i>A user account has been found with the received email address.</i>
- <i>The email address has been verified.</i>
- <i>Checked by the `email-address-verified-f` function.</i>

In order to use the `check-email-address` protocol function, you have to provide
the following working functions as parameters.

```
(defn my-route
  [{{:keys [email-address]} :params :as request}]
  (check-email-address request {:email-address-registered-f         (fn [] "This function must return TRUE if the received email address is registered in your system.")
                                :email-address-valid-f              (fn [] "This function must return TRUE if the received email address is valid.")
                                :email-address-verified-f           (fn [] "This function must return TRUE if the received email address is verified by the user.")
                                :too-many-attempts-by-email-address (fn [] "This function must return TRUE if your log service shows that the received email address has
                                                                            been used up for too many attempts to do the checking in a recent timeframe.")
                                :too-many-attempts-by-ip-address    (fn [] "This function must return TRUE if your log service shows that the IP address of the client has
                                                                            been initiated the checking process too many times in a recent timeframe.")
                                :optional-check-f                   (fn [] "This function adds an optional custom stage of checking to the protocol. If returns false,
                                                                            the protocol function returns an error response.")}))
```

### The `check-phone-number` protocol

The [`user-protocols.api/check-phone-number`](documentation/clj/user-protocols/API.md/#check-phone-number)
function applies the `check-phone-number` protocol.

This protocol function could return with the following HTTP responses:

| Response body |     | Description | Checked by |
| ------------- | --- | --- | --- |
| <sub>`:invalid-request/missing-ip-address`</sub> | <sub>`400`</sub> | <sub>No IP address is found in the request.</sub> | <sub>By the actual protocol function.</sub> |
| <sub>`:invalid-request/missing-user-agent`</sub> | <sub>`400`</sub> | <sub>No user agent is found in the request.</sub> | <sub>By the actual protocol function.</sub> |
| <sub>`:illegal-client-behaviour/invalid-phone-number-received`</sub> | <sub>`403`</sub> | <sub>Invalid phone number has been received.</sub> | <sub>`phone-number-valid-f`</sub> |
| <sub>`:too-many-requests/too-many-attempts-by-phone-number`</sub>    | <sub>`429`</sub> | <sub>Too many actions has been attempted in a specific timeframe.</sub> |
| <sub>`:invalid-request/missing-ip-address`</sub> | <sub>`400`</sub> | <sub>No IP address is found in the request.</sub> |
| <sub>`:invalid-request/missing-user-agent`</sub> | <sub>`400`</sub> | <sub>No IP address is found in the request.</sub> |
| <sub>`:invalid-request/missing-ip-address`</sub> | <sub>`400`</sub> | <sub>No IP address is found in the request.</sub> |
| <sub>`:invalid-request/missing-user-agent`</sub> | <sub>`400`</sub> | <sub>No IP address is found in the request.</sub> |


{:too-many-requests/too-many-attempts-by-phone-number :status 429}


- <i>Too many actions has been attempted in a specific timeframe.</i>
- <i>Checked by the `too-many-attempts-by-phone-number-f` function.</i>

```
{:too-many-requests/too-many-attempts-by-ip-address :status 429}
```

- <i>Too many actions has been attempted in a specific timeframe.</i>
- <i>Checked by the `too-many-attempts-by-ip-address-f` function.</i>

```
{:unknown-error/optional-check-stage-failed :status 520}
```

- <i>The optional custom check function returned a false value.</i>
- <i>Checked by the `optional-check-f` function.</i>

```
{:standard-activity/unregistered-phone-number-received :status 200}
```

- <i>No user account has been found with the received phone number.</i>
- <i>Checked by the `phone-number-registered-f` function.</i>

```
{:standard-activity/unverified-phone-number-received :status 200}
```

- <i>A user account has been found with the received phone number.</i>
- <i>The phone number has not been verified yet.</i>
- <i>Checked by the `phone-number-verified-f` function.</i>

```
{:standard-activity/verified-phone-number-received :status 200}
```

- <i>A user account has been found with the received phone number.</i>
- <i>The phone number has been verified.</i>
- <i>Checked by the `phone-number-verified-f` function.</i>

In order to use the `check-phone-number` protocol function, you have to provide
the following working functions as parameters.

```
(defn my-route
  [{{:keys [phone-number]} :params :as request}]
  (check-phone-number request {:phone-number-registered-f         (fn [] "This function must return TRUE if the received email address is registered in your system.")
                               :phone-number-valid-f              (fn [] "This function must return TRUE if the received email address is valid.")
                               :phone-number-verified-f           (fn [] "This function must return TRUE if the received email address is verified by the user.")
                               :too-many-attempts-by-phone-number (fn [] "This function must return TRUE if your log service shows that the received email address has
                                                                          been used up for too many attempts to do the checking in a recent timeframe.")
                               :too-many-attempts-by-ip-address   (fn [] "This function must return TRUE if your log service shows that the IP address of the client has
                                                                          been initiated the checking process too many times in a recent timeframe.")
                               :optional-check-f                  (fn [] "This function adds an optional custom stage of checking to the protocol. If returns false,
                                                                          the protocol function returns an error response.")}))
```

### The `create-user-account` protocol

The [`user-protocols.api/create-user-account`](documentation/clj/user-protocols/API.md/#create-user-account)
function creates a user account.

This protocol function could return with the following HTTP responses:

###### HTTP status 400 (invalid request)

- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the `check-phone-number` function.

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the `check-phone-number` function.

###### HTTP status 403 (illegal client behaviour)

- `{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`
  - Invalid email address has been received (despite the client-side form validation).
  - Checked by negating the return value of the given `email-address-valid-f` function.
- `{:body :illegal-client-behaviour/invalid-password-received :status 403}`
  - Invalid password has been received (despite the client-side form validation).
  - Checked by negating the return value of the given `password-valid-f` function.
- `{:body :illegal-client-behaviour/invalid-user-data-received :status 403}`
  - Invalid user data has been received (despite the client-side form validation).
  - Checked by negating the return value of the given `user-data-valid-f` function.
- `{:body :illegal-client-behaviour/user-already-logged-in :status 403}`
  - The client has a valid authenticated user session and trying to create a new
    user account (registration form must be only available for unauthenticated visitors).
  - Checked by evaluating the return value of the given `user-logged-in-f` function
    as a boolean.
- `{:body :illegal-client-behaviour/email-address-already-registered :status 403}`
  - The received email address has been already connected to another user account
    (registration form must check the availability of the email address).
  - Checked by evaluating the return value of the given `email-address-registered-f`
    function as a boolean.

###### HTTP status 429 (too many attempts by the client)

- `{:body :too-many-requests/too-many-attempts-by-email-address :status 429}`
  - User account creating has been attempted with the received email address at
    least X times in a specific timeframe.
  - Checked by evaluating the return value of the given `too-many-attempts-by-email-address-f`
    function as a boolean.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - User account creating has been attempted by the same IP address at least X times
    in a specific timeframe (an IP address could belong to a workplace with different
    client devices with a shared IP address).
  - Checked by evaluating the return value of the given `too-many-attempts-by-ip-address-f`
    function as a boolean.

###### HTTP status 500 (server error)
- `{:body :server-error/unable-to-create-user-account :status 500}`
  - User account creating has been failured.
  - Checked by evaluating the return value of the given `create-user-account-f`
    function as a boolean.

###### HTTP status 520 (unknown error)
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by evaluating the return value of the given `optional-check-f` function
    as a boolean.

###### HTTP status 200 (standard activity)

- `{:body :standard-activity/unable-to-send-welcome-email :status 200}`
  - Unable to send welcome email.
  - Checked by evaluating the return value of the given `send-welcome-email-f`
    function as a boolean.
  - The client should warn the user about checking for typos.
- `{:body :standard-activity/user-account-created :status 200}`
  - The user account has been successfully created.
  - Checked by evaluating the return value of the given `create-user-account-f`
    function as a boolean.

In order to use the `create-user-account` protocol function, you have to provide
the following working functions as parameters.

```
(defn my-route
  [request]
  (create-user-account request {:create-user-account-f                (fn [] ...)
                                :email-address-registered-f           (fn [] ...)
                                :email-address-valid-f                (fn [] ...)
                                :password-valid-f                     (fn [] ...)
                                :send-welcome-email-f                 (fn [] ...)
                                :user-data-valid-f                    (fn [] ...)
                                :user-logged-in-f                     (fn [] ...)
                                :too-many-attempts-by-email-address-f (fn [] ...)
                                :too-many-attempts-by-ip-address-f    (fn [] ...)
                                :too-many-failure-by-email-address-f  (fn [] ...)}))
```

You could pass a custom security stage for the `create-user-account` function:

```
(defn my-route
  [request]
  (create-user-account request {:optional-check-f (fn [] ...)
                                ...}))
```

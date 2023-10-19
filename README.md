
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

```
(defn my-route
  [{{:keys [email-address]} :params :as request}])
  (check-email-address request {:email-address-registered-f         (fn [] "This function must return TRUE if the received email address is registered in your system.")
                                :email-address-valid-f              (fn [] "This function must return TRUE if the received email address is valid.")
                                :email-address-verified-f           (fn [] "This function must return TRUE if the received email address is verified by the user.")
                                :too-many-attempts-by-email-address (fn [] "This function must return TRUE if your log service shows that the received email address has
                                                                            been used up for too many attempts to do the checking in a recent timeframe.")
                                :too-many-attempts-by-ip-address    (fn [] "This function must return TRUE if your log service shows that the IP address of the client has
                                                                            been initiated the checking process too many times in a recent timeframe.")}))})
```

If no security concern has been found, the `check-email-address` function could
return a HTTP response that looks like any of the followings:

- `{:body :standard-activity/unregistered-email-address-received :status 200}`
- `{:body :standard-activity/unverified-email-address-received   :status 200}`
- `{:body :standard-activity/verified-email-address-received     :status 200}`

If any security concern has been found, the return value could be something like this:

`{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`

The whole list of possible return values of the `check-email-address` function from
this example could be found below.

### Possible HTTP responses

###### HTTP status 400 (invalid request)

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the actual protocol function.
- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the actual protocol function.

###### HTTP status 403 (illegal client behaviour)

- `{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`
  - Invalid email address has been received (despite the client-side form validation).
  - Checked by negating the return value of the given `email-address-valid-f` function.

###### HTTP status 429 (too many attempts by the client)

- `{:body :too-many-requests/too-many-attempts-by-email-address :status 429}`
  - Too many actions has been attempted with the received email address in a specific timeframe.
  - Checked by evaluating the return value of the given `too-many-attempts-by-email-address-f`
    function as a boolean.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - Too many actions has been attempted by the same IP address in a specific timeframe
    (an IP address could belong to a workplace with different client devices with a shared IP address).
  - Checked by evaluating the return value of the given `too-many-attempts-by-ip-address-f`
    function as a boolean.

###### HTTP status 520 (unknown error)
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by evaluating the return value of the given `optional-check-f` function
    as a boolean.

###### HTTP status 200 (standard activity)

- `{:body :standard-activity/unregistered-email-address-received :status 200}`
  - No user has been found with the received email address.
  - Checked by negating the return value of the given `email-address-registered-f` function.
  - The client should recommend registration to the user.
- `{:body :standard-activity/unverified-email-address-received :status 200}`
  - A user account has been found with the received email address.
  - The email address of the found user account is NOT verified.
  - Checked by negating the return value of the given `email-address-verified-f` function.
  - The client should recommend email address verification to the user.
- `{:body :standard-activity/verified-email-address-received :status 200}`
  - A user account has been found with the received email address.
  - The email address of the found user account is verified.
  - Checked by evaluating the return value of the given `email-address-verified-f`
    function as a boolean.
  - The client should recommend logging in to the user.

### The `check-email-address` protocol

The [`user-protocols.api/check-email-address`](documentation/clj/user-protocols/API.md/#check-email-address)
function checks whether an email address is:

- unknown      (not registered)
- not verified (but registered)
- verified     (and registered)

This protocol function could return with the following HTTP responses:

| Response body                                              | Response status |
| ---------------------------------------------------------- | --------------- |
| `:invalid-request/missing-user-agent`                      | `400`           |
| No user agent is found in the request. Automatically checked by the actual protocol function.|
| |
| `:invalid-request/missing-ip-address`                      | `400`           |
| `:illegal-client-behaviour/invalid-email-address-received` | `403`           |
| `:too-many-requests/too-many-attempts-by-email-address`    | `429`           |
| `:too-many-requests/too-many-attempts-by-ip-address`       | `429`           |
| `:unknown-error/optional-check-stage-failed`               | `520`           |
| `:standard-activity/unregistered-email-address-received`   | `200`           |
| `:standard-activity/unverified-email-address-received`     | `200`           |
| `:standard-activity/verified-email-address-received`       | `200`           |

In order to use the `check-email-address` protocol function, you have to provide
the following working functions as parameters.

```
(defn my-route
  [request]
  (check-email-address request {:email-address-registered-f         (fn [] ...)
                                :email-address-valid-f              (fn [] ...)
                                :email-address-verified-f           (fn [] ...)
                                :too-many-attempts-by-email-address (fn [] ...)
                                :too-many-attempts-by-ip-address    (fn [] ...)}))
```

You could pass a custom security stage for the `check-email-address` function:

```
(defn my-route
  [request]
  (check-email-address request {:optional-check-f (fn [] ...)
                                ...}))
```

### The `check-phone-number` protocol

The [`user-protocols.api/check-phone-number`](documentation/clj/user-protocols/API.md/#check-phone-number)
function checks whether a phone number is:

- unknown      (not registered)
- not verified (but registered)
- verified     (and registered)

This protocol function could return with the following HTTP responses:

###### HTTP status 400 (invalid request)

- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the `check-phone-number` function.

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the `check-phone-number` function.

###### HTTP status 403 (illegal client behaviour)

- `{:body :illegal-client-behaviour/invalid-phone-number-received :status 403}`
  - Invalid phone number has been received (despite the client-side form validation).
  - Checked by negating the return value of the given `phone-number-valid-f` function.

###### HTTP status 429 (too many attempts by the client)

- `{:body :too-many-requests/too-many-attempts-by-phone-number :status 429}`
  - Phone number checking has been attempted with the received phone number at
    least X times in a specific timeframe.
  - Checked by evaluating the return value of the given `too-many-attempts-by-phone-number-f`
    function as a boolean.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - Phone number checking has been attempted by the same IP address at least X times
    in a specific timeframe (an IP address could belong to a workplace with different
    client devices with a shared IP address).
  - Checked by evaluating the return value of the given `too-many-attempts-by-ip-address-f`
    function as a boolean.

###### HTTP status 520 (unknown error)
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by evaluating the return value of the given `optional-check-f` function
    as a boolean.

###### HTTP status 200 (standard activity)

- `{:body :standard-activity/unregistered-phone-number-received :status 200}`
  - No user has been found with the received phone number.
  - Checked by negating the return value of the given `phone-number-registered-f` function.
  - The client should recommend registration to the user.
- `{:body :standard-activity/unverified-phone-number-received :status 200}`
  - A user account has been found with the received phone number.
  - The phone number of the found user account is NOT verified.
  - Checked by negating the return value of the given `phone-number-verified-f` function.
  - The client should recommend phone number verification to the user.
- `{:body :standard-activity/verified-phone-number-received :status 200}`
  - A user account has been found with the received phone number.
  - The phone number of the found user account is verified.
  - Checked by evaluating the return value of the given `phone-number-verified-f`
    function as a boolean.
  - The client should recommend logging in to the user.

In order to use the `check-phone-number` protocol function, you have to provide
the following working functions as parameters.

```
(defn my-route
  [request]
  (check-phone-number request {:phone-number-registered-f         (fn [] ...)
                               :phone-number-valid-f              (fn [] ...)
                               :phone-number-verified-f           (fn [] ...)
                               :too-many-attempts-by-phone-number (fn [] ...)
                               :too-many-attempts-by-ip-address   (fn [] ...)}))
```

You could pass a custom security stage for the `check-phone-number` function:

```
(defn my-route
  [request]
  (check-phone-number request {:optional-check-f (fn [] ...)
                               ...}))
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

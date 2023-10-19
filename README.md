
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

- [How check an email address?](#how-to-check-an-email-address)

- [How check a phone number?](#how-to-check-a-phone-number)

- [How create a user account?](#how-to-create-a-user-account)

### Abbreviations

- `EAS code`:  Email address security code, for user actions that require multi-factor authentication.
- `EAV code`:  Email address verification code, for user email address verification.
- `EANP pair`: Email address and password pair, for email address based login method.
- `PNNP pair`: Phone number and password pair, for phone number based login method.
- `PNS code`:  Phone number security code, for user actions that require multi-factor authentication.
- `PNV code`:  Phone number verification code, for user phone number verification.

### How to check an email address?

The [`user-protocols.api/check-email-address`](documentation/clj/user-protocols/API.md/#check-email-address)
function checks whether an email address is:

- unknown      (not registered)
- not verified (but registered)
- verified     (and registered)

This function could return with the following cases:

`HTTP status 400 (invalid request)`

- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the `check-email-address` function.

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the `check-email-address` function.

`HTTP status 403 (illegal client behaviour)`

- `{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`
  - Invalid email address has been received (despite the client-side form validation).
  - Checked by the given `email-address-valid-f` function (its output is negated).

`HTTP status 429 (too many attempts by the client)`

- `{:body :too-many-requests/too-many-attempts-by-email-address :status 429}`
  - Email address checking has been attempted with the received email address at
    least X times in a specific timeframe.
  - Checked by the given `too-many-attempts-by-email-address-f` function.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - Email address checking has been attempted by the same IP address at least X times
    in a specific timeframe (an IP address could belong to a workplace with different
    client devices with a shared IP address).
  - Checked by the given `too-many-attempts-by-ip-address-f` function.

`HTTP status 520 (unknown error)`
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by the return value of the given `optional-check-f` function
    (its output is evaluated as boolean).

`HTTP status 200 (standard activity)`

- `{:body :standard-activity/unregistered-email-address-received :status 200}`
  - No user has been found with the received email address.
  - Checked by the given `email-address-registered-f` function (its output is negated).
  - The client should recommend registration to the user.
- `{:body :standard-activity/unverified-email-address-received :status 200}`
  - A user account has been found with the received email address.
  - The email address of the found user account is NOT verified.
  - Checked by the given `email-address-verified-f` function (its output is negated).
  - The client should recommend email address verification to the user.
- `{:body :standard-activity/verified-email-address-received :status 200}`
  - A user account has been found with the received email address.
  - The email address of the found user account is verified.
  - Checked by the given `email-address-verified-f` function.
  - The client should recommend logging in to the user.

> Protocol functions are only applying security logic, they are not doing any
  environmental checking and not making any side effects! To use them, you have
  to provide the working functions for them!

```
(defn my-check-email-address
  [request]
  (check-email-address request {:email-address-registered-f         (fn [] ...)
                                :email-address-valid-f              (fn [] ...)
                                :email-address-verified-f           (fn [] ...)
                                :too-many-attempts-by-email-address (fn [] ...)
                                :too-many-attempts-by-ip-address    (fn [] ...)}))
```

You could pass a custom security stage for the `check-email-address` function:

```
(defn my-check-email-address
  [request]
  (check-email-address request {:optional-check-f (fn [] ...)
                                ...}))
```

### How to check a phone number?

The [`user-protocols.api/check-phone-number`](documentation/clj/user-protocols/API.md/#check-phone-number)
function checks whether a phone number is:

- unknown      (not registered)
- not verified (but registered)
- verified     (and registered)

This function could return with the following cases:

`HTTP status 400 (invalid request)`

- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the `check-phone-number` function.

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the `check-phone-number` function.

`HTTP status 403 (illegal client behaviour)`

- `{:body :illegal-client-behaviour/invalid-phone-number-received :status 403}`
  - Invalid phone number has been received (despite the client-side form validation).
  - Checked by the given `phone-number-valid-f` function (its output is negated).

`HTTP status 429 (too many attempts by the client)`

- `{:body :too-many-requests/too-many-attempts-by-phone-number :status 429}`
  - Phone number checking has been attempted with the received phone number at
    least X times in a specific timeframe.
  - Checked by the given `too-many-attempts-by-phone-number-f` function.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - Phone number checking has been attempted by the same IP address at least X times
    in a specific timeframe (an IP address could belong to a workplace with different
    client devices with a shared IP address).
  - Checked by the given `too-many-attempts-by-ip-address-f` function.

`HTTP status 520 (unknown error)`
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by the return value of the given `optional-check-f` function
    (its output is evaluated as boolean).

`HTTP status 200 (standard activity)`

- `{:body :standard-activity/unregistered-phone-number-received :status 200}`
  - No user has been found with the received phone number.
  - Checked by the given `phone-number-registered-f` function (its output is negated).
  - The client should recommend registration to the user.
- `{:body :standard-activity/unverified-phone-number-received :status 200}`
  - A user account has been found with the received phone number.
  - The phone number of the found user account is NOT verified.
  - Checked by the given `phone-number-verified-f` function (its output is negated).
  - The client should recommend phone number verification to the user.
- `{:body :standard-activity/verified-phone-number-received :status 200}`
  - A user account has been found with the received phone number.
  - The phone number of the found user account is verified.
  - Checked by the given `phone-number-verified-f` function.
  - The client should recommend logging in to the user.

> Protocol functions are only applying security logic, they are not doing any
  environmental checking and not making any side effects! To use them, you have
  to provide the working functions for them!

```
(defn my-check-phone-number
  [request]
  (check-phone-number request {:phone-number-registered-f        (fn [] ...)
                               :phone-number-valid-f              (fn [] ...)
                               :phone-number-verified-f           (fn [] ...)
                               :too-many-attempts-by-phone-number (fn [] ...)
                               :too-many-attempts-by-ip-address   (fn [] ...)}))
```

You could pass a custom security stage for the `check-phone-number` function:

```
(defn my-check-phone-number
  [request]
  (check-phone-number request {:optional-check-f (fn [] ...)
                               ...}))
```

### How to create a user account?

The [`user-protocols.api/create-user-account`](documentation/clj/user-protocols/API.md/#create-user-account)
function creates a user account.

This function could return with the following cases:

`HTTP status 400 (invalid request)`

- `{:body :invalid-request/missing-user-agent :status 400}`
  - No user agent is found in the request.
  - Automatically checked by the `check-phone-number` function.

- `{:body :invalid-request/missing-ip-address :status 400}`
  - No IP address is found in the request.
  - Automatically checked by the `check-phone-number` function.

`HTTP status 403 (illegal client behaviour)`

- `{:body :illegal-client-behaviour/invalid-email-address-received :status 403}`
  - Invalid email address has been received (despite the client-side form validation).
  - Checked by the given `email-address-valid-f` function (its output is negated).
- `{:body :illegal-client-behaviour/invalid-password-received :status 403}`
  - Invalid password has been received (despite the client-side form validation).
  - Checked by the given `password-valid-f` function (its output is negated).
- `{:body :illegal-client-behaviour/invalid-user-data-received :status 403}`
  - Invalid user data has been received (despite the client-side form validation).
  - Checked by the given `user-data-valid-f` function (its output is negated).
- `{:body :illegal-client-behaviour/user-already-logged-in :status 403}`
  - The client has a valid authenticated user session and trying to create a new
    user account (registration form must be only available for unauthenticated visitors).
  - Checked by the given `user-logged-in-f` function.
- `{:body :illegal-client-behaviour/email-address-already-registered :status 403}`
  - The received email address has been already connected to another user account
    (registration form must check the availability of the email address).
  - Checked by the given `email-address-registered-f` function.

`HTTP status 429 (too many attempts by the client)`

- `{:body :too-many-requests/too-many-attempts-by-email-address :status 429}`
  - User account creating has been attempted with the received email address at
    least X times in a specific timeframe.
  - Checked by the given `too-many-attempts-by-email-address-f` function.
- `{:body :too-many-requests/too-many-attempts-by-ip-address :status 429}`
  - User account creating has been attempted by the same IP address at least X times
    in a specific timeframe (an IP address could belong to a workplace with different
    client devices with a shared IP address).
  - Checked by the given `too-many-attempts-by-ip-address-f` function.

`HTTP status 500 (server error)`
- `{:body :server-error/unable-to-create-user-account :status 500}`
  - User account creating has been failured.
  - Checked by the return value of the given `create-user-account-f` function
    (its output is evaluated as boolean).

`HTTP status 520 (unknown error)`
- `{:body :unknown-error/optional-check-stage-failed :status 520}`
  - The given `optional-check-f` function has been returned a false value.
  - Checked by the return value of the given `optional-check-f` function
    (its output is evaluated as boolean).

`HTTP status 200 (standard activity)`

- `{:body :standard-activity/unable-to-send-welcome-email :status 200}`
  - Unable to send welcome email.
  - Checked by the return value of the given `send-welcome-email-f` function (its
    output is evaluated as boolean).
  - The client should warn the user about checking for typos.
- `{:body :standard-activity/user-account-created :status 200}`
  - The user account has been successfully created.
  - Checked by the return value of the given `create-user-account-f` function (its
    output is evaluated as boolean).

> Protocol functions are only applying security logic, they are not doing any
  environmental checking and not making any side effects! To use them, you have
  to provide the working functions for them!

```
(defn my-create-user-account
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
(defn my-create-user-account
  [request]
  (create-user-account request {:optional-check-f (fn [] ...)
                                ...}))
```

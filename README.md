
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

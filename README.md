
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

- [In general](#in-general)

### In general

This library is a collection of protocol functions that contain composed security
checks for the most common user account actions. These protocol functions apply
security checks by utilizing working functions provided as parameters.
They do not perform environmental checks or have any side effects on their own.

For further information about the protocol functions check the [functional documentation](documentation/COVER.md)
or [source code](source-code/clj/user_protocols/protocols.clj).

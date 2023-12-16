
# clj-security-protocols

### Overview

The <strong>clj-security-protocols</strong> is a set of security protocol functions
for database, media upload and user handling in Clojure projects.

### deps.edn

```
{:deps {bithandshake/clj-security-protocols {:git/url "https://github.com/bithandshake/clj-security-protocols"
                                             :sha     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}
```

### Current version

Check out the latest commit on the [release branch](https://github.com/bithandshake/clj-security-protocols/tree/release).

### Documentation

The <strong>clj-security-protocols</strong> functional documentation is [available here](https://bithandshake.github.io/clj-security-protocols).

### Changelog

You can track the changes of the <strong>clj-security-protocols</strong> library [here](CHANGES.md).

# Usage

> Some parameters of the following functions and some further functions are not discussed in this file.
  To learn more about the available functionality, check out the [functional documentation](documentation/COVER.md)!

### Index

- [In general](#in-general)

### In general

This library is a collection of protocol functions that contain composed security
checks for the most common database, media upload and user account actions. These
protocol functions apply security checks by utilizing working functions provided
as parameters. They do not perform environmental checks or have any side effects
on their own.


(ns user-protocols.api
    (:require [user-protocols.protocols :as protocols]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

; user-protocols.protocols
(def check-user-contact                   protocols/check-user-contact)
(def create-user-account                  protocols/create-user-account)
(def drop-user-session                    protocols/drop-user-session)
(def remove-user-account                  protocols/remove-user-account)
(def send-security-code-authenticated     protocols/send-security-code-authenticated)
(def send-security-code-unauthenticated   protocols/send-security-code-unauthenticated)
(def update-user-contact                  protocols/update-user-contact)
(def update-user-account                  protocols/update-user-account)
(def verify-security-code-authenticated   protocols/verify-security-code-authenticated)
(def verify-security-code-unauthenticated protocols/verify-security-code-unauthenticated)
(def verify-user-password                 protocols/verify-user-password)
(def verify-user-pin-code                 protocols/verify-user-pin-code)


(ns user-security-protocols.api
    (:require [user-security-protocols.protocols :as protocols]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

; @redirect (user-security-protocols.protocols)
(def check-user-identifier                protocols/check-user-identifier)
(def create-user-account                  protocols/create-user-account)
(def drop-user-session                    protocols/drop-user-session)
(def recover-user-password                protocols/recover-user-password)
(def remove-user-account                  protocols/remove-user-account)
(def send-security-code-authenticated     protocols/send-security-code-authenticated)
(def send-security-code-unauthenticated   protocols/send-security-code-unauthenticated)
(def update-username                      protocols/update-username)
(def update-user-contact                  protocols/update-user-contact)
(def update-user-data                     protocols/update-user-data)
(def verify-security-code-authenticated   protocols/verify-security-code-authenticated)
(def verify-security-code-unauthenticated protocols/verify-security-code-unauthenticated)
(def verify-user-password                 protocols/verify-user-password)
(def verify-user-pin-code                 protocols/verify-user-pin-code)

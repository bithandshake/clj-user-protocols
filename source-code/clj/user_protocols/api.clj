
(ns user-protocols.api
    (:require [user-protocols.protocols :as protocols]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

; user-protocols.protocols
(def check-email-address             protocols/check-email-address)
(def check-phone-number              protocols/check-phone-number)
(def create-user-account             protocols/create-user-account)
(def remove-user-account             protocols/remove-user-account)
(def send-eas-code-authenticated     protocols/send-eas-code-authenticated)
(def send-eas-code-unauthenticated   protocols/send-eas-code-unauthenticated)
(def send-eav-code-authenticated     protocols/send-eav-code-authenticated)
(def send-eav-code-unauthenticated   protocols/send-eav-code-unauthenticated)
(def send-pns-code-authenticated     protocols/send-pns-code-authenticated)
(def send-pns-code-unauthenticated   protocols/send-pns-code-unauthenticated)
(def send-pnv-code-authenticated     protocols/send-pnv-code-authenticated)
(def send-pnv-code-unauthenticated   protocols/send-pnv-code-unauthenticated)
(def update-email-address            protocols/update-email-address)
(def update-phone-number             protocols/update-phone-number)
(def update-user-account             protocols/update-user-account)
(def verify-eas-code-authenticated   protocols/verify-eas-code-authenticated)
(def verify-eas-code-unauthenticated protocols/verify-eas-code-unauthenticated)
(def verify-eav-code-authenticated   protocols/verify-eav-code-authenticated)
(def verify-eav-code-unauthenticated protocols/verify-eav-code-unauthenticated)
(def verify-pns-code-authenticated   protocols/verify-pns-code-authenticated)
(def verify-pns-code-unauthenticated protocols/verify-pns-code-unauthenticated)
(def verify-pnv-code-authenticated   protocols/verify-pnv-code-authenticated)
(def verify-pnv-code-unauthenticated protocols/verify-pnv-code-unauthenticated)

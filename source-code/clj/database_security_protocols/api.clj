
(ns database-security-protocols.api
    (:require [database-security-protocols.protocols :as protocols]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

; database-security-protocols.protocols
(def get-data    protocols/get-data)
(def store-data  protocols/store-data)
(def remove-data protocols/remove-data)

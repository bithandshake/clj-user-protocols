
(ns database-security-protocols.protocols
    (:require [fruits.audit.api :as audit]
              [fruits.http.api  :as http]))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn get-data
  ; @important
  ; This function is not tested and may not behave as expected.
  ;
  ; @description
  ; Security protocol function for getting data from the database.
  ;
  ; @note
  ; - For performing additional side effects use the 'additional-action-f' function (applied if no security check has been failed).
  ; - For implementing additional security levels use the 'additional-security-f' function (applied as last security check).
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - The data validating / manipulating functions are applied as a cascade where every function takes the data as it has returned from
  ;   the previous function (except the first function that takes the initial data) and every function must return the validated / manipulated
  ;   data in case of successful execution.
  ; - The data validating / manipulating functions are applied in the following order:
  ;   1. get-data-f
  ;   2. data-valid-f
  ;   3. prepare-data-f
  ;   4. populate-data-f
  ;   5. hide-sensitive-values-f
  ;   6. parse-values-f
  ;   7. unparse-values-f
  ;   8. postpare-data-f
  ;
  ; @param (map) request
  ; @param (*)(opt) initial-data
  ; The 'initial-data' passed through the data validating / manipulating functions (that are applied as a cascade).
  ; Default: NIL
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)          Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)        Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt) Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :data-valid-f (function)(opt)                 Must return the data if it's valid.
  ;  :get-data-f (function)(opt)                   Must return the data if the execution was successful.
  ;  :hide-sensitive-values-f (function)(opt)      Must return the data if the execution was successful.
  ;  :parse-values-f (function)(opt)               Must return the data if the execution was successful.
  ;  :permission-granted-f (function)(opt)         Must return TRUE if the user has permission to do the action.
  ;  :populate-data-f (function)(opt)              Must return the data if the execution was successful.
  ;  :postpare-data-f (function)(opt)              Must return the data if the execution was successful.
  ;  :prepare-data-f (function)(opt)               Must return the data if the execution was successful.
  ;  :unparse-values-f (function)(opt)             Must return the data if the execution was successful.
  ;  :user-rate-limit-exceeded-f (function)(opt)   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (get-data {...} {...})
  ;
  ; @usage
  ; (get-data {...} {...} {...})
  ;
  ; @usage
  ; (get-data {...} {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @usage
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-id    (-> request :session :user-id)]
  ;        (get-data request {:my-data "My initial data (optional)"}
  ;                          {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                           :data-valid-f                 #(map? %)
  ;                           :get-data-f                   #(my-database/get-data!             %)
  ;                           :parse-values-f               #(my-utils/parse-timestamps-in-data %)
  ;                           :populate-data-f              #(my-utils/add-user-related-values  %)
  ;                           :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id? user-id)})))
  ; =>
  ; {:body {:my-data "..."} :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/permission-denied            (The user has no permission to do the action),
  ;   :invalid-request/invalid-ip-address             (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent             (No valid user agent has been found in the request),
  ;   :too-many-requests/client-rate-limit-exceeded   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded     (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed (The additional security function returned a false value)
  ;   :server-error/unable-to-get-data                (The 'get-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-hide-sensitive-values   (The 'hide-sensitive-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-parse-values            (The 'parse-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-populate-data           (The 'populate-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-postpare-data           (The 'postpare-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-prepare-data            (The 'prepare-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-unparse-values          (The 'unparse-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-validate-data           (The 'data-valid-f' function has been returned a falsish value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  ([request functions]
   (get-data request nil functions))

  ([request initial-data {:keys [additional-action-f
                                 additional-security-f
                                 client-rate-limit-exceeded-f
                                 data-valid-f
                                 get-data-f
                                 hide-sensitive-values-f
                                 parse-values-f
                                 permission-granted-f
                                 populate-data-f
                                 postpare-data-f
                                 prepare-data-f
                                 unparse-values-f
                                 user-rate-limit-exceeded-f]}]
   (let [ip-address (http/request->ip-address request)
         user-agent (http/request->user-agent request)]
        (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
              (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
              (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
              (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
              (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
              (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
              (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
              ; After every provided security function has been passed, it applies the data validating / manipulating functions.
              :getting-data ; The 'apply-cascade-f' function applies the given 'f' function (if any) on the given data. Otherwise, it returns the data.
                            (letfn [(apply-cascade-f [f data] (if f (f  data) data))]
                                   (as-> initial-data % (or (apply-cascade-f get-data-f              %) {:body :server-error/unable-to-get-data              :status 500})
                                                        (or (apply-cascade-f data-valid-f            %) {:body :server-error/unable-to-validate-data         :status 500})
                                                        (or (apply-cascade-f prepare-data-f          %) {:body :server-error/unable-to-prepare-data          :status 500})
                                                        (or (apply-cascade-f populate-data-f         %) {:body :server-error/unable-to-populate-data         :status 500})
                                                        (or (apply-cascade-f hide-sensitive-values-f %) {:body :server-error/unable-to-hide-sensitive-values :status 500})
                                                        (or (apply-cascade-f parse-values-f          %) {:body :server-error/unable-to-parse-values          :status 500})
                                                        (or (apply-cascade-f unparse-values-f        %) {:body :server-error/unable-to-unparse-values        :status 500})
                                                        (or (apply-cascade-f postpare-data-f         %) {:body :server-error/unable-to-postpare-data         :status 500})
                                                        {:body % :status 200}))))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn store-data
  ; @important
  ; This function is not tested and may not behave as expected.
  ;
  ; @description
  ; Security protocol function for storing data in the database.
  ;
  ; @note
  ; - For performing additional side effects use the 'additional-action-f' function (applied if no security check has been failed).
  ; - For implementing additional security levels use the 'additional-security-f' function (applied as last security check).
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ; - The data validating / manipulating functions are applied as a cascade where every function takes the data as it has returned from
  ;   the previous function (except the first function that takes the initial data) and every function must return the validated / manipulated
  ;   data in case of successful execution.
  ; - The data validating / manipulating functions are applied in the following order:
  ;   1. data-valid-f
  ;   2. prepare-data-f
  ;   3. unpopulate-data-f
  ;   4. remove-blank-values-f
  ;   5. parse-values-f
  ;   6. unparse-values-f
  ;   7. postpare-data-f
  ;   8. store-data-f
  ;
  ; @param (map) request
  ; @param (*)(opt) initial-data
  ; The 'initial-data' passed through the data validating / manipulating functions (that are applied as a cascade).
  ; Default: NIL
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)          Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)        Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt) Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :data-valid-f (function)(opt)                 Must return the data only if it's valid.
  ;  :parse-values-f (function)(opt)               Must return the data if the execution was successful.
  ;  :permission-granted-f (function)(opt)         Must return TRUE if the user has permission to do the action.
  ;  :postpare-data-f (function)(opt)              Must return the data if the execution was successful.
  ;  :prepare-data-f (function)(opt)               Must return the data if the execution was successful.
  ;  :remove-blank-values-f (function)(opt)        Must return the data if the execution was successful.
  ;  :store-data-f (function)(opt)                 Must return TRUE if the execution was successful.
  ;  :unparse-values-f (function)(opt)             Must return the data if the execution was successful.
  ;  :unpopulate-data-f (function)(opt)            Must return the data if the execution was successful.
  ;  :user-rate-limit-exceeded-f (function)(opt)   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (store-data {...} {...})
  ;
  ; @usage
  ; (store-data {...} {...} {...})
  ;
  ; @usage
  ; (store-data {...} {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @usage
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-id    (-> request :session :user-id)]
  ;        (store-data request {:my-data "My initial data (optional)"}
  ;                            {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                             :data-valid-f                 #(map? %)
  ;                             :parse-values-f               #(my-utils/parse-timestamps-in-data   %)
  ;                             :store-data-f                 #(my-database/store-data!             %)
  ;                             :unpopulate-data-f            #(my-utils/remove-user-related-values %)
  ;                             :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id? user-id)})))
  ; =>
  ; {:body :performed-request/data-stored :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/permission-denied            (The user has no permission to do the action),
  ;   :invalid-request/invalid-ip-address             (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent             (No valid user agent has been found in the request),
  ;   :performed-request/data-stored                  (The provided data has been successfully stored)
  ;   :server-error/unable-to-parse-values            (The 'parse-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-postpare-data           (The 'postpare-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-prepare-data            (The 'prepare-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-remove-blank-values     (The 'remove-blank-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-store-data              (The 'store-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-unparse-values          (The 'unparse-values-f' function has been returned a falsish value),
  ;   :server-error/unable-to-unpopulate-data         (The 'unpopulate-data-f' function has been returned a falsish value),
  ;   :server-error/unable-to-validate-data           (The 'data-valid-f' function has been returned a falsish value),
  ;   :too-many-requests/client-rate-limit-exceeded   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded     (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  ([request functions]
   (store-data request nil functions))

  ([request initial-data {:keys [additional-action-f
                                 additional-security-f
                                 client-rate-limit-exceeded-f
                                 data-valid-f
                                 parse-values-f
                                 permission-granted-f
                                 postpare-data-f
                                 prepare-data-f
                                 remove-blank-values-f
                                 store-data-f
                                 unparse-values-f
                                 unpopulate-data-f
                                 user-rate-limit-exceeded-f]}]
   (let [ip-address (http/request->ip-address request)
         user-agent (http/request->user-agent request)]
        (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
              (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
              (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
              (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
              (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
              (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
              (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
              ; After every provided security function has been passed, it applies the data validating / manipulating functions.
              :storing-data ; The 'apply-cascade-f' function applies the given 'f' function (if any) on the given data. Otherwise, it returns the data.
                            (letfn [(apply-cascade-f [f data] (if f (f  data) data))]
                                   (as-> initial-data % (or (apply-cascade-f data-valid-f          %) {:body :server-error/unable-to-validate-data       :status 500})
                                                        (or (apply-cascade-f prepare-data-f        %) {:body :server-error/unable-to-prepare-data        :status 500})
                                                        (or (apply-cascade-f unpopulate-data-f     %) {:body :server-error/unable-to-unpopulate-data     :status 500})
                                                        (or (apply-cascade-f remove-blank-values-f %) {:body :server-error/unable-to-remove-blank-values :status 500})
                                                        (or (apply-cascade-f parse-values-f        %) {:body :server-error/unable-to-parse-values        :status 500})
                                                        (or (apply-cascade-f unparse-values-f      %) {:body :server-error/unable-to-unparse-values      :status 500})
                                                        (or (apply-cascade-f postpare-data-f       %) {:body :server-error/unable-to-postpare-data       :status 500})
                                                        (or (apply-cascade-f store-data-f          %) {:body :server-error/unable-to-store-data          :status 500})
                                                        {:body :performed-request/data-stored :status 200}))))))

;; ----------------------------------------------------------------------------
;; ----------------------------------------------------------------------------

(defn remove-data
  ; @important
  ; This function is not tested and may not behave as expected.
  ;
  ; @description
  ; Security protocol function for removing data from the database.
  ;
  ; @note
  ; - For performing additional side effects use the 'additional-action-f' function (applied if no security check has been failed).
  ; - For implementing additional security levels use the 'additional-security-f' function (applied as last security check).
  ; - Performs various security checks before returns a HTTP response that indicates if any check has been failed or the action was successful.
  ;
  ; @param (map) request
  ; @param (map) functions
  ; {:additional-action-f (function)(opt)          Must return TRUE in case of successful execution.
  ;  :additional-security-f (function)(opt)        Must return TRUE in case of no security concern detected.
  ;  :client-rate-limit-exceeded-f (function)(opt) Must return TRUE if the client device / IP address is involved in too many attempts in a specific timeframe.
  ;  :remove-data-f (function)                     Must return TRUE if the execution was successful.
  ;  :user-rate-limit-exceeded-f (function)(opt)   Must return TRUE if the user is involved in too many attempts in a specific timeframe.}
  ;
  ; @usage
  ; (remove-data {...} {...})
  ;
  ; @usage
  ; (remove-data {...} {...})
  ; =>
  ; {:body :too-many-requests/user-rate-limit-exceeded :status 429}
  ;
  ; @usage
  ; (defn my-route
  ;   [request]
  ;   (let [ip-address (-> request :remote-addr)
  ;         user-id    (-> request :session :user-id)]
  ;        (remove-data request {:client-rate-limit-exceeded-f #(my-log-service/too-many-attempts-by-ip-address? ip-address)
  ;                              :remove-data-f                #(my-database/remove-data!)
  ;                              :user-rate-limit-exceeded-f   #(my-log-service/too-many-attempts-by-user-id? user-id)})))
  ; =>
  ; {:body :performed-request/data-removed :status 200}
  ;
  ; @return (map)
  ; {:body (namespaced keyword)
  ;   :forbidden-request/permission-denied            (The user has no permission to do the action),
  ;   :invalid-request/invalid-ip-address             (No valid IP address has been found in the request),
  ;   :invalid-request/invalid-user-agent             (No valid user agent has been found in the request),
  ;   :performed-request/data-removed                 (The data has been successfully removed)
  ;   :server-error/unable-to-remove-data             (The 'remove-data-f' function has been returned a falsish value),
  ;   :too-many-requests/client-rate-limit-exceeded   (Too many actions have been attempted by the client device / IP address in a specific timeframe),
  ;   :too-many-requests/user-rate-limit-exceeded     (Too many actions have been attempted by the user in a specific timeframe),
  ;   :unknown-error/additional-action-stage-failed   (The additional action function returned a false value),
  ;   :unknown-error/additional-security-stage-failed (The additional security function returned a false value)
  ;  :status (integer)
  ;   200, 400, 403, 429, 500, 520}
  [request {:keys [additional-action-f
                   additional-security-f
                   client-rate-limit-exceeded-f
                   permission-granted-f
                   remove-data-f
                   user-rate-limit-exceeded-f]}]
  (let [ip-address (http/request->ip-address request)
        user-agent (http/request->user-agent request)]
       (cond (not (audit/ip-address-valid? ip-address))                                  {:body :invalid-request/invalid-ip-address             :status 400}
             (not (audit/user-agent-valid? user-agent))                                  {:body :invalid-request/invalid-user-agent             :status 400}
             (and client-rate-limit-exceeded-f (boolean (client-rate-limit-exceeded-f))) {:body :too-many-requests/client-rate-limit-exceeded   :status 429}
             (and user-rate-limit-exceeded-f   (boolean (user-rate-limit-exceeded-f)))   {:body :too-many-requests/user-rate-limit-exceeded     :status 429}
             (and permission-granted-f         (not (permission-granted-f)))             {:body :forbidden-request/permission-denied            :status 403}
             (and additional-security-f        (not (additional-security-f)))            {:body :unknown-error/additional-security-stage-failed :status 520}
             (and additional-action-f          (not (additional-action-f)))              {:body :unknown-error/additional-action-stage-failed   :status 520}
             (not (remove-data-f))                                                       {:body :server-error/unable-to-remove-data             :status 500}
             :data-removed                                                               {:body :performed-request/data-removed                 :status 200})))

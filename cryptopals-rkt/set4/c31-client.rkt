#lang racket

; Challenge 31
;; Implement and Break HMAC-SHA1 with an Artificial Timing Leak
(require "c28.rkt"
         "../set1/c1.rkt"
         net/http-client)

; This file is the client side to be paired with c31-server.
; As explained in the server file, there is a strange
; lag every few requests, so c31.rkt will use a simulated
; web server for the timimng attack. I'm keeping this just
; because.

(define DEBUG #true)
(define DELAY 0.05)
; open-connection : void -> http-conn
;; opens a connection to localhost at port 4321
(define (open-connection)
  (http-conn-open "localhost"
                  #:port 4321
                  #:auto-reconnect? #t))

; close-connection : http-conn -> void
;; closes the given connection
(define close-connection http-conn-close!)

; send-request : http-conn string -> bytes? (listof bytes?) input-port
;; sends a request to the connection
(define (send-request conn fname fsig)
  (http-conn-sendrecv! conn
                       (string-append
                        "/filerequest"
                        "?file="
                        fname
                        "&signature="
                        fsig)))

; timeit : (list -> any) list -> real
;; times the execution of the given closure
(define (timeit f lst)
  ; so it turns out time-apply is vastly more accurate than
  ; using current-inexact-milliseconds
  (define-values (res t-time r-time g-time)
    (time-apply f lst))
  r-time)

; timing-attack : void -> bytes
;; executes the timing attack on the fake server
(define (timing-attack)
  (define conn (open-connection))
  (foldl (λ (_ known-bytes)
           (crack-next-byte conn known-bytes))
         #""
         (build-list 20 values))
  (http-conn-abandon! conn))

; crack-next-byte : bytes -> bytes
;; discovers the next byte of the HMAC using the
;; previously known bytes
(define (crack-next-byte conn known-bytes)
  ; expected-lag is caluclated as such:
  ;  it always lags at least DELAY ms for each byte of
  ;  known bytes.
  ;  The delay for when is correct, is that amount + DELAY
  ;  but to allow for some flexibility, let's reduce it just a bit
  (define expected-lag
    (+ (* DELAY (bytes-length known-bytes))
       (* DELAY 0.75)))
  (define result
    (for/last ([i (in-range 0 256)])
      (define mac
        (bytes->string/utf-8
         (ascii->hex
          (bytes-append known-bytes
                        (bytes i)
                        (make-bytes (- 19 (bytes-length known-bytes)))))))
      (define t
        (timeit (λ (m)
                  (send-request conn "secret.txt" m))
                (list mac)))
      (when DEBUG
        (printf "MAC: ~v---~v//~v\n"
                (ascii->hex (bytes i)) t expected-lag))
      #:final (>= t expected-lag)
      i))
  (when DEBUG
    (printf "~v\n" (ascii->hex (bytes result))))
  (bytes-append known-bytes (bytes result)))

(timing-attack)
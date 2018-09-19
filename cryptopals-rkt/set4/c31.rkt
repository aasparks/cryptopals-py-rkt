#lang racket

; Challenge 31
;; Implement and Break HMAC-SHA1 with an Artificial Timing Leak
(require "c28.rkt"
         "../set1/c1.rkt"
         net/http-client)

(define DEBUG #f)

;;; The psuedocode on Wikipedia should be enough. HMAC is very easy.

;;; Using the web framework of your choosing, write a tiny application
;;; that has a URL that takes a 'file' argument and a 'signature' argument,
;;; like so:
;;; http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51

;;; Have the server generate an HMAC key, and then verify that the 'signature'
;;; on incoming requests is valid for 'file', using the "==" operator to compare
;;; the valid MAC for a file with the 'signature' parameter (in other words, verify
;;; the HMAC the way any normal programmer would verify it).

;;; Write a function, call it 'insecure_compare', that implements the ==
;;; operation by doing byte-at-a-time comparisons with early exit.

;;; In the loop for 'insecure_compare', add a 50ms sleep (sleep 50ms after each
;;; byte check).

;;; Use your 'insecure_compare' function to verify the HMACs on incoming requests,
;;; and test that the whole contraption works. Return a 500 if the MAC is invalid,
;;; and a 200 if it's OK.

; Okay, I did all that in c31-server.rkt

;;; Using the timing leak in this application, write a program that discovers the
;;; valid MAC for any file.

; open http connection to localhost at port 9000
(define http-connection
  (http-conn-open "localhost"
                #:port 9000))

; send a file and signature and determine whether
; it is valid
(define (validate-file fname fsig)
  (define-values
    (status headers input-port)
    (http-conn-sendrecv!
     http-connection
     (string-append "/file-request?"
                    "file="
                    "secret.txt"
                    "&signature="
                    "deadbeef")))
  (not
   (string-contains? (bytes->string/utf-8 status)
                     "500 Error")))

; Okay so the attack on a timing leak is easy.
; Just try every possible value for the signature
; and each time it takes an extra half second,
; the byte is correct
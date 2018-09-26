#lang racket
(require web-server/servlet
         web-server/servlet-env
         web-server/http
         web-server/http/bindings
         racket/random
         "../set1/c1.rkt"
         "../set1/c2.rkt"
         "../sha1/sha1.rkt")

; This provides an http web server for the timing
; attack. However, every 5th or so packet, experiences
; serious lag and I have no idea why. This makes a
; timing attack completely invalid. I'm keeping this
; here for, I don't know, posterity? Maybe I'll come to
; learn this lag is my fault. Until then, this problem
; will be solved with a simulated web server instead.

(define DEBUG #true)

#|
   The psuedocode on Wikipedia should be enough. HMAC is
   very easy.
|#
; hmac : bytes bytes -> bytes
;; creates the hashed message authentication code
;; as defined by the pseudocode on Wikipedia
(define (hmac key message)
  (define k (cond
              [(> (bytes-length key) 64)
               ; shorten key by hashing it
               (bytes-append
                (sha-1 key)
                (make-bytes (- 64 20) 0))]
              [(< (bytes-length key) 64)
               ; pad with 0's to the right
               (bytes-append
                key
                (make-bytes (- 64 (bytes-length key)) 0))]
              [else key]))
  (define o-pad (xorstrs k (make-bytes 64 #x5c)))
  (define i-pad (xorstrs k (make-bytes 64 #x36)))
  (sha-1
   (bytes-append o-pad
                 (sha-1 (bytes-append i-pad message)))))

#|
   Using the web framework of your choosing
   (Sinatra, web.py, whatever), write a tiny
   application that has a URL that takes a
   "file" argument and a "signature" argument,
   like so:
     http://localhost:9000/test?file=foo&signature=bar
|#

; start : request -> response
;; starts the server and parses requests
(define (start req)
  (cond
    [(can-parse-request? req)
     (validate-request req)]
    [else
     (response/xexpr
      `(html (head (title "File Request"))
             (body (p "Make request"))))]))

; can-parse-request? : request -> boolean
;; determines if a request has a file and
;; a signature argument
(define (can-parse-request? req)
  (define bindings (request-bindings req))
  (and (exists-binding? 'file bindings)
       (exists-binding? 'signature bindings)))

#|
   Have the server generate an HMAC key, and then verify
   that the "signature" on incoming requests is valid
   for the "file", using the "==" operator to compare
   the valid MAC for a file with the "signature" parameter.
|#
(define KEY (crypto-random-bytes 16))

; validate-request : request -> response
;; determines if the request for a given file
;; with the given signature is a valid request
(define (validate-request req)
  (define bindings (request-bindings req))
  (define fname (extract-binding/single 'file bindings))
  (define fsig (hex->ascii (string->bytes/utf-8 (extract-binding/single 'signature bindings))))
  (define actual-sig (hmac KEY (string->bytes/utf-8 fname)))
  (if (insecure-compare fsig actual-sig)
      (response 200
                #"Valid MAC"
                (current-seconds)
                TEXT/HTML-MIME-TYPE
                empty
                (λ (out)
                  (write-bytes
                   #"<html><body>Correct MAC</body></html>"
                   out)))
      (response 500
                #"Invalid MAC"
                (current-seconds)
                TEXT/HTML-MIME-TYPE
                empty
                (λ (out)
                  (write-bytes
                   #"<html><body>Invalid MAC</body></html>"
                   out)))))

#|
   Write a function, call it "insecure-compare", that
   implements the == operation by doing byte-at-a-time
   comparisons with early exit.

   In the loop for "insecure-compare", add a 50ms sleep.

   Use your "insecure-compare" function to verify the HMACs
   on incoming requests, and test that the whole contraption
   works. Return a 500 if the MAC is invalid, and a 200
   if it's OK.
|#

(define DELAY 50)
(define DELAY_SEC (/ DELAY 1000))

; insecure-compare : bytes bytes -> boolean
;; compares two strings for inequality with an
;; artificial timing leak inserted
(define (insecure-compare s1 s2)
  (if (not (= (bytes-length s1) (bytes-length s2)))
      #false
      (for/last ([i (in-range (bytes-length s1))])
        (define result
          (equal? (bytes-ref s1 i)
                  (bytes-ref s2 i)))
        (when result (sleep DELAY_SEC))
        #:final (not result)
        result)))

(when DEBUG
  (printf "~v\n" (ascii->hex (hmac KEY #"secret.txt"))))
 
(serve/servlet start
               #:port 4321
               #:servlet-path "/filerequest")
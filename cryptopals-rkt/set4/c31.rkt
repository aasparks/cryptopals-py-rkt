#lang racket

; Challenge 31
;; Implement and Break HMAC-SHA1 with an Artificial Timing Leak
(require "../sha1/sha1.rkt"
         "../set1/c1.rkt"
         "../set1/c2.rkt"
         racket/random)

(define DEBUG #true)

(provide hmac
         timeit
         server-request)

;;; This file contains the true result for the challenge.
;;; As explained in the -client and -server files, there
;;; is a strange lag, so this file simulates the web server
;;; in the most basic of ways. Maybe one day I'll figure out
;;; how to get the web server version working.

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

; server-request : bytes bytes -> integer
;; simulates a server request to determine if the
;; provided tag is correct for the given file
(define (server-request file signature)
  (if (signature-valid? file signature)
      200
      500))

#|
   Have the server generate an HMAC key, and then verify
   that the "signature" on incoming requests is valid
   for the "file", using the "==" operator to compare
   the valid MAC for a file with the "signature" parameter.
|#
(define KEY (crypto-random-bytes 16))

; signature-valid? : bytes bytes -> boolean
;; determines if the given signature is valid
;; using an unsecured comparison function
(define (signature-valid? file signature)
  (insecure-compare (hmac KEY file)
                    signature))
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

; timing-attack : void -> bytes
;; executes the timing attack on the fake server
(define (timing-attack)
  (foldl (λ (_ known-bytes)
           (crack-next-byte known-bytes))
         #""
         (build-list 20 values)))

; crack-next-byte : bytes -> bytes
;; discovers the next byte of the HMAC using the
;; previously known bytes
(define (crack-next-byte known-bytes)
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
        (bytes-append known-bytes
                      (bytes i)
                      (make-bytes (- 19 (bytes-length known-bytes)))))
      (define t
        (timeit (λ (m)
                  (server-request #"secret.txt" m))
                (list mac)))
      #;(when DEBUG
        (printf "MAC: ~v---~v//~v\n"
                (ascii->hex (bytes i)) t expected-lag))
      #:final (>= t expected-lag)
      i))
  (when DEBUG
    (printf "~v\n" (ascii->hex (bytes result))))
  (bytes-append known-bytes (bytes result)))

; timeit : (list -> any) list -> real
;; times the execution of the given closure
(define (timeit f lst)
  ; so it turns out time-apply is vastly more accurate than
  ; using current-inexact-milliseconds
  (define-values (res t-time r-time g-time)
    (time-apply f lst))
  r-time)

(module+ test
  (require rackunit)

  ;;; HMAC Tests
  ; test vectors come from
  ; https://tools.ietf.org/html/rfc2202
  ; 1
  (check-equal?
   (ascii->hex (hmac (make-bytes 20 #x0b)
                     #"Hi There"))
   #"b617318655057264e28bc0b6fb378c8ef146be00")
  ; 2
  (check-equal?
   (ascii->hex (hmac #"Jefe"
                     #"what do ya want for nothing?"))
   #"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
  ; 3
  (check-equal?
   (ascii->hex (hmac (make-bytes 20 #xaa)
                     (make-bytes 50 #xdd)))
   #"125d7342b9ac11cd91a39af48aa17b4f63f175d3")
  ; 4
  (check-equal?
   (ascii->hex
    (hmac (hex->ascii #"0102030405060708090a0b0c0d0e0f10111213141516171819")
          (make-bytes 50 #xcd)))
   #"4c9007f4026250c6bc8414f9bf50c86c2d7235da")
  ; 5
  (check-equal?
   (ascii->hex
    (hmac (make-bytes 20 #x0c)
          #"Test With Truncation"))
   #"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")
  ; 6
  (check-equal?
   (ascii->hex
    (hmac (make-bytes 80 #xaa)
          #"Test Using Larger Than Block-Size Key - Hash Key First"))
   #"aa4ae5e15272d00e95705637ce8a3b55ed402112")
  ; 7
  (check-equal?
   (ascii->hex
    (hmac (make-bytes 80 #xaa)
          #"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"))
   #"e8e99d0f45237d786d6bbaa7965c7808bbff1a91")
  
  ;;; INSECURE-COMPARE Tests
  (check-true (insecure-compare #"abcd" #"abcd"))
  (check-false (insecure-compare #"abcd" #"abce"))
  (check-false (insecure-compare #"abc" #"a"))
  
  ;;; TIMEIT Tests
  (check-equal? (timeit insecure-compare (list #"abcd" #"abcd"))
                (* DELAY 4))
  (check-equal? (timeit insecure-compare (list #"abce" #"abcd"))
                (* DELAY 3))
  
  ;;; Actual Attack  
  (define expected (ascii->hex (hmac KEY #"secret.txt")))
  (when DEBUG
    (printf "The correct MAC is ~v\n" expected))
  (check-equal? (ascii->hex (timing-attack))
                expected))
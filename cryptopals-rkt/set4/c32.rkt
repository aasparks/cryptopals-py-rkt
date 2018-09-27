#lang racket

; Challenge 32
;; Break HMAC-SHA1 with a Slightly Less Artificial Timing Leak

(require racket/random
         "../set1/c1.rkt"
         "../set1/c2.rkt"
         "c31.rkt")

; DEBUG
(define DEBUG #true)

#|
   Reduce the sleep in your 'insecure_compare' until
   your previous solution breaks.
   Now break it again.
|#

;;; The previous solution broke at a delay of
;;; 30ms.
;;; With this solution, I can get to the answer
;;; in somewhat reasonable amount of time with
;;; a delay of 20ms but no less.
;;; As for going all the way down to 5ms, I'm at a
;;; loss. Maybe it can be improved some though...

; Delay 
(define DELAY 20) 
(define DELAY-SEC (/ DELAY 1000))

; Key
(define KEY (crypto-random-bytes 16))

; server-request : bytes bytes -> integer
;; simulates a server request to determine if the
;; provided tag is correct for the given file
(define (server-request file signature)
  (if (signature-valid? file signature)
      200
      500))

; signature-valid? : bytes bytes -> boolean
;; determines if the given signature is valid
;; using an unsecured comparison function
(define (signature-valid? file signature)
  (insecure-compare (hmac KEY file)
                    signature))

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
        (when result (sleep DELAY-SEC))
        #:final (not result)
        result)))

; timing-attack : void -> bytes
;; executes the timing attack on the fake server.
;; The new timing-attack will go backwards if it needs
;; to. It can potentially loop forever, but it shouldn't.
(define (timing-attack)
  (timing-attack-helper #""))

; timing-attack-helper : bytes -> bytes
;; recursively calls crack-next-byte until all
;; bytes have been found
(define (timing-attack-helper known-bytes)
  (when DEBUG
    (printf "~v\n" (ascii->hex known-bytes)))
  (if (= (bytes-length known-bytes) 20)
      known-bytes
      (timing-attack-helper (crack-next-byte known-bytes))))

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
       (* DELAY 0.8)))
  (crack-next-helper known-bytes expected-lag 0))

; crack-next-helper : bytes real real -> bytes
;; recursively searches for the byte that is needed.
;; if the byte is not found, it sends back known-bytes
;; without the last byte because that means the last byte
;; was discovered incorrectly
(define (crack-next-helper known-bytes expected-lag i)
  (define mac
    (bytes-append
     known-bytes
     (bytes i)
     (make-bytes (- 19 (bytes-length known-bytes)))))
  (define t
    (timeit server-request (list #"secret.txt" mac)))
  (cond
    [(>= t expected-lag) (bytes-append known-bytes (bytes i))]
    [(= i 255) (subbytes known-bytes 0 (sub1 (bytes-length known-bytes)))]
    [else (crack-next-helper known-bytes expected-lag (add1 i))]))

; NOTE: the recursive solution is so much nicer
(module+ test
  (require rackunit)
  
  (define expected
    (ascii->hex (hmac KEY #"secret.txt")))
  (when DEBUG
    (printf "~v\n" expected))
  (check-equal? expected
                (ascii->hex (timing-attack))))
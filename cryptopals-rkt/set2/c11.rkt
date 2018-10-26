#lang racket/base

; Challenge 11
;; An ECB/CBC Detection Oracle
(require racket/random
         racket/list
         "../util/conversions.rkt"
         "../util/aes.rkt"
         "../util/pkcs7.rkt"
         "../set1/c8.rkt")

#|
   Now that you have ECB and CBC working:

   Write a function to generate a random AES key; that's just
   16 random bytes.

   Write a function that encrypts data under an unknown key ---
   that is, a function that generates a random key and encrypts
   under it.

   The function should look like
     encryption-oracle(your-input) => [MEANINGLESS JIBBER JABBER]

   Under the hood, have the function append 5-10 bytes before the
   plaintext and 5-10 bytes after the plaintext.

   Now have the function choose to encrypt under ECB 1/2 the time,
   and under CBC the other half (just use random IV's each time
   for CBC). Use rand(2) to decide which to use.

   Detect the block cipher mode the function is using each time. You
   should end up with a piece of code that, pointed at a black box
   that might be encrypting ECB or CBC, tells which one is happening.
|#

; for testing, we will keep a box that stores which
; one was used each time
(define expected (box '()))

; encryption-oracle : bytes -> bytes
;; encrypts using an unknown mode with random
;; data inserted
(define (encryption-oracle txt)
  (define key (crypto-random-bytes 16))
  (define ecb (random-ref (list #t #f)))
  ; log for testing
  (set-box! expected (flatten (list (unbox expected) ecb)))
  (define pre (crypto-random-bytes (random 5 11)))
  (define post (crypto-random-bytes (random 5 11)))
  (define pt (pkcs7-pad (bytes-append pre txt post)))
  (aes-128-encrypt pt key #:mode (if ecb 'ecb 'cbc)))

; ecb-or-cbc : bytes -> boolean
;; returns true if the ciphertext was encrypted using
;; ECB mode and false if CBC 
(define ecb-or-cbc is-ecb?)

(module+ test
  (require rackunit
           racket/file
           "../util/test.rkt")

  ;; we'll use this plaintext so it is sufficiently long
  (define test-key #"YELLOW SUBMARINE")
  (define test-iv (make-bytes 16 0))
  (define pt
    (aes-128-decrypt
     (base64->ascii (file->bytes "../../testdata/10.txt"))
     test-key
     test-iv
     #:mode 'cbc))

  (define challenge-11
    (test-suite
     "Challenge 11"
    (check-equal?
     (for/list ([i (in-range 50)]) ; run 50 times
       (ecb-or-cbc (encryption-oracle pt)))
     (unbox expected))))
  (time-test challenge-11))
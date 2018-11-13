#lang racket/base

; Challenge 39
;; Implement RSA
(require racket/random
         math/number-theory
         "../util/conversions.rkt")
(provide rsa-keygen
         primegen
         rsa-encrypt
         rsa-decrypt)
#|
   There are two annoying things about implementing RSA.
   Both of them involve key generation; the actual
   encryption/decryption in RSA is trivial.

   First, you need to generate random primes. You can't
   just agree on a prime ahead of time, like you do in DH.
   You can write this algorithm yourself, but I just cheat
   and use OpenSSL's BN library to do the work.

   The second is that you need an "invmod" operation
   (the multiplicative inverse), which is not an operation
   that is wired into your langauge. The algorithm is just
   a couple lines, but I always lose an hour getting it to
   work.

   I recommend you not bother with primegen, but do take the
   time to get your own EGCD and "invmod" algorithm working.

   Now:
      * Generate 2 random primes. We'll use small numbers to
        start, so you can just pick them out of a prime table.
        Call them "p" and "q"
      * Let n be p * q. Your RSA math is modulo n.
      * Let et be (p-1)*(q-1) (the "totient"). You'll need
        this value only for keygen.
      * Let e be 3.
      * Compute d = invmod(e, et) invmod(17, 3120) is 2753
      * Your public key is [e,n]. Your private key is [d,n].
      * To encrypt: c = m**e % n. To decrypt: m = c**d % n
      * Test this out with a number, like "42"
      * Repeat with bignum primes (keep e=3)

   Finally, to encrypt a string, do something cheesy, like
   convert the string to hex and put "0x" on the front of it
   to turn it into a number. The math cares not how stupidly
   you feed it strings.
|#

;;; Racket does not have it's own way to generate
;;; large primes. I'm doing a modified Miller-Rabin
;;; here because prime? has already been written for
;;; me. I have no idea how it works under the hood
;;; but it is amazingly fast.

; generate-prime-candidate : void -> integer?
;; generates a random number of 1024 bytes, sets
;; the lsb and msb
(define (generate-prime-candidate [size 128])
  (bytes->integer
   (xorstrs (crypto-random-bytes size)
            (bytes-append #"\x80"
                          (make-bytes (- size 2) 0)
                          #"\x01"))))

; primegen : void -> integer?
;; generates a prime number
(define (primegen [size 64])
  (let loop ()
    (define p (generate-prime-candidate size))
    (if (prime? p) p (loop))))

; rsa-primegen : void -> integer? integer?
;; generates two prime numbers (p, q) for RSA
(define (rsa-primegen [e 3])
  ; okay, so modular-inverse fails the majority of
  ; the time. after some googling I discovered there
  ; needs to be a validity check. If (sub1 p) % e == 0,
  ; it causes the fail. So we check for the that first.
  (define (gen-valid-prime [other 0])
    (let loop ([p (primegen)])
      (if (or (= other p)
              (zero? (modulo (sub1 p) e)))
          (loop (primegen))
          p)))
  (values (gen-valid-prime) (gen-valid-prime)))

; rsa-keygen : void -> (cons integer? integer?) (cons integer? integer?)
;; generates rsa public, private key pair
(define (rsa-keygen [e 3])
  (define-values (p q) (rsa-primegen e))
  (define n (* p q))
  (define et (* (sub1 p) (sub1 q)))
  (define d (modular-inverse e et))
  (values (cons e n) (cons d n)))

; rsa-encrypt : bytes? integer? integer? -> bytes?
;; encrypts the txt using RSA under the given public key
(define (rsa-encrypt txt pub)
  (integer->bytes
   (modular-expt (bytes->integer txt)
                 (car pub) (cdr pub))))

; rsa-decrypt : bytes? integer? integer? -> bytes?
;; decrypts the given txt using RSA under the given private key
(define rsa-decrypt rsa-encrypt) ; it's the same

(module+ test
  (require rackunit
           "../util/test.rkt")

  (define-values (pub priv) (rsa-keygen))
  (define msg #"Who lives in a pineapple under the sea?")

  (define test-challenge-39
    (test-suite
     "Challenge 39"
     (check-equal? (rsa-decrypt (rsa-encrypt msg pub) priv)
                   msg)))

  (time-test test-challenge-39))

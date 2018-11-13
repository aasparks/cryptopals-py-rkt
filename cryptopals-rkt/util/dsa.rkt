#lang racket/base

;; My implementation of DSA signature
;; generation and verification.
;; I'm using FIPS 186-4.

;; The problem statement allows me to skip the
;; parameter generation, so I'm doing just that.

(require math/number-theory
         racket/random
         sha
         "../util/conversions.rkt")

(provide dsa-sign
         dsa-verify)

; dsa-sign : bytes? integer? integer? integer? -> (cons/c integer? integer?)
;; signs for the message using DSA private key
(define (dsa-sign message p q g x)
  (define k (modulo (bytes->integer (crypto-random-bytes 512)) q))
  (define r (modulo (modular-expt g k p) q))
  (cond
    [(zero? r) (dsa-sign message p q g x)]
    [else (define s (modulo (* (modular-inverse k q)
                               (+ (sha256 message)
                                  (* x r)))
                            q))
          (if (zero? s)
              (dsa-sign message p q g x)
              (cons r s))]))

; dsa-verify : bytes? bytes? (cons/c integer? integer?) -> boolean?
;; verifies the message, signature using DSA public key
(define (dsa-verify message signature p q g y)
  (define r (car signature))
  (define s (cdr signature))
  (define valid (and (< 0 r) (< r q) (< 0 s) (< s q)))
  (cond
    [valid (define w (modular-inverse s q))
           (define u1 (modulo (* w (sha256 message)) q))
           (define u2 (modulo (* r w) q))
           (define v (modulo (modulo (* (expt g u1) (expt y u2)) p) q))
           (= v r)]

    [else #false]))

(module+ test
  (require rackunit)

  (define p (bytes->integer
             (hex->ascii
              (bytes-append
               #"800000000000000089e1855218a0e7dac38136ffafa72eda7"
               #"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
               #"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
               #"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
               #"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
               #"1a584471bb1"))))
  (define q (bytes->integer
             (hex->ascii #"f4f47f05794b256174bba6e9b396a7707e563c5b")))
  (define g (bytes->integer
             (hex->ascii
              (bytes-append
               #"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
               #"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
               #"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
               #"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
               #"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
               #"9fc95302291"))))
  )
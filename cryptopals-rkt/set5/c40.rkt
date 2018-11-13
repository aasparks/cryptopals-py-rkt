#lang racket/base

; Challenge 40
;; Implement an E=3 RSA Broadcast Attack
(require math/number-theory
         racket/class
         "../util/rsa.rkt"
         "../util/conversions.rkt")
(provide DumbRSAServer%
         nth-root)
#|
   Assume you're a javascript programmer. That is, you're
   using a naive handrolled RSA to encrypt without padding.

   Assume you can be coerced into encrypting the same plaintext
   three times, under three different public keys. You can;
   it's happened.

   Then an attacker can trivially decrypt your message, by:
      1. Capturing any 3 of the ciphertexts and their
         corresponding pubkeys
      2. Using the CRT to solve for the number represented
         by the three ciphertexts (which are residues mod
         their respective pubkeys)
      3. Taking the cube root of the resulting number

   The CRT says you can take any number and represent it as
   the combination of a series of residues mod a series of
   moduli. In the three-residue case, you have:
      result = (+ (* c0 ms0 (invmod ms0 n0))
                  (* c1 ms1 (invmod ms1 n1))
                  (* c2 ms2 (invmod ms2 n2)))

   where
      c0, c1, and c2 are the three respective residues mod
      n0, n1, and n2

      msn (for n in 0,1,2) are the product of the moduli
      EXCEPT n_n --- ie, ms1 is n0*n2

      N_012 is the product of all three moduli

   To decrypt RSA using a simple cube root, leave off the
   final modulus operation; just take the raw accumulated
   result and cube-root it.
|#
(define DumbRSAServer%
  (class object%
    (init)
    (super-new)

    (define e 3)

    (define/public (encrypt txt)
      (define-values (pub priv) (rsa-keygen))
      (define ctxt (rsa-encrypt txt pub))
      (values ctxt pub))))

; break-server : bytes? DumbRSAServer%
;; attacks the dumb RSA server and gets the ptxt back
(define (break-server ptxt server)
  (define-values (c0 n0) (send server encrypt ptxt))
  (define-values (c1 n1) (send server encrypt ptxt))
  (define-values (c2 n2) (send server encrypt ptxt))
  (set!-values (n0 n1 n2) (apply values (map cdr (list n0 n1 n2))))
  (define m0 (* n1 n2))
  (define m1 (* n0 n2))
  (define m2 (* n0 n1))
  (define result
    (modulo
     (+ (* m0 (bytes->integer c0)
           (modular-inverse m0 n0))
        (* m1 (bytes->integer c1)
           (modular-inverse m1 n1))
        (* m2 (bytes->integer c2)
           (modular-inverse m2 n2)))
     (* n0 n1 n2)))
  (integer->bytes (nth-root result 3)))

; nth-root : integer? integer? -> integer?
;; finds the n'th root of a number. pcode stolen from wiki.
(define (nth-root num root)
  (define (guess g step)
    (define w (expt (+ g step) root))
    (cond
      [(= w num) (+ g step)]
      [(< w num) (guess g (arithmetic-shift step 1))]
      [(= step 1) g]
      [else (guess (+ g (arithmetic-shift step -1)) 1)]))
  (guess 1 1))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (check-equal? (nth-root 9 2) 3)
  (check-equal? (nth-root 8 3) 2)

  (define server (new DumbRSAServer%))
  (define ptxt #"Spongebob Squarepants")
  (check-equal? (break-server ptxt server) ptxt))
#lang racket/base

; Challenge 41
;; Implement Unpadded Message Recovery Oracle
(require racket/class
         racket/math
         math/number-theory
         sha
         "../util/conversions.rkt"
         "../util/rsa.rkt")
#|
   Nate Lawson says we should stop calling it "RSA padding"
   and start calling it "RSA armoring"; here's why.

   Imagine a web application, again with the Javascript
   encryption, taking RSA-encrypted messages which
   (again: Javascript) aren't padded before encryption
   at all.

   You can submit an arbitrary RSA blob and the server
   will return plaintext. But you can't submit the same
   message twice: let's say the server keeps hashes
   of previous messages for some liveness interval, and
   that the message has an embedded timestamp:
   {
      time: 13563042762,
      social: '555-55-5555'
   }

   You'd like to capture other people's messages and
   use the server to decrypt them. But when you try,
   the server takes the hash of the ciphertext and
   uses it to reject the request. Any bit you flip in
   the ciphertext irrevocably scrambles the decryption.

   This turns out to be trivially breakable:
      * Capture the ciphertext C
      * Let N and E be the public modulus and exponent
        respectively
      * Let S be a random number > 1 mod N. Doesn't matter what.
      * Now:
         C' = ((S**E mod N) C ) mod N
      * Submit C', which appears totally different from
        C, to the server, recovering P', which appears
        totally different from P
      * Now
                P'
          P=  ----- mod N
                S

   Oops!

   Implement that attack.
|#
(define UnpaddedRSAServer%
  (class object%
    (init)
    (super-new)

    (define-values (pub priv) (rsa-keygen))
    (define msgs (list))

    (define/public (encrypt message)
      (values (rsa-encrypt message pub) pub))

    (define/public (decrypt message)
      (when (member (sha256 message) msgs)
        (error 'decrypt "Already sent message"))
      (append msgs (sha256 message))
      (rsa-decrypt message priv))))

; attack-server : (is-a UnpaddedRSAServer%) bytes? -> bytes?
;; attacks the dumb RSA server using the attack described
(define (attack-server server message)
  (define-values (ctxt pub) (send server encrypt message))
  (define-values (E N) (values (car pub) (cdr pub)))
  (define ptxt (send server decrypt ctxt))
  (define S (random 2 4294967087))
  (define c-prime (modulo
                   (* (modular-expt S E N)
                      (bytes->integer ctxt))
                   N))
  (define p-prime (send server decrypt (integer->bytes c-prime)))
  (define p (modulo (* (bytes->integer p-prime)
                       (modular-inverse S N))
                    N))
  (integer->bytes p))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (define server (new UnpaddedRSAServer%))
  (define message #"Attack at dawn!")
  (define test-challenge-41
    (test-suite
     "Challenge 41"
     (check-equal? (attack-server server message)
                   message)))
  (time-test test-challenge-41))
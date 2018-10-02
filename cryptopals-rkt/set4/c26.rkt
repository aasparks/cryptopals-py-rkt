#lang racket

; Challenge 26
;; CTR Bitflipping
(require racket/random
         "../aes/aes.rkt"
         "../set1/c2.rkt"
         "../set2/c9.rkt")

#|
   There are people in the world that believe that CTR resists bit
   flipping attacks of the kind to which CBC mode is susceptible.
   Re-implement the CBC bitflipping exercise from earlier to use CTR
   mode instead of CBC mode. Inject an "admin=true" token.
|#

; So let's just copy & paste the code from challenge 16
(define KEY (crypto-random-bytes 16))
(define PRE #"comment1=cooking%20MCs;userdata=")
(define POST #";comment2=%20like%20a%20pound%20of%20bacon")

; encryption-oracle : bytes -> bytes
;; sanitizes, appends, and prepends the set byte strings,
;; and encrypts the input under a secret key
(define (encryption-oracle txt)
  (define sanitized
    (list->bytes
     (remove #\;
             (remove #\= (bytes->list txt)))))
  (define input (bytes-append PRE sanitized POST))
  (aes-128-ctr input KEY 0)) ;this is CTR now

; is-admin? : bytes -> boolean
;; Decryption function
;; Determines if the decrypted cookie contains an admin profile
(define (is-admin? ct)
  (string-contains?
   (bytes->string/latin-1 ; because the block gets scrambled, it isn't a well-formed utf-8
     (aes-128-ctr
      ct KEY 0))
   ";admin=true;"))


;; This is where it gets different.
;; The CTR crack is actually easier.
;; Notice:
;;;  PT ^ KEY = CT
;;;  CT ^ KEY = PT
;;;  PT ^ ATTACK = MY_PT
;;;  CT ^ KEY ^ ATTACK = MY_PT
;; The question becomes: what should ATTACK look like?
;; It actually looks the same as the CBC attack, but instead
;; of attacking the previous block, you attack the one you want.

; ctr-bitflip : void -> boolean
;; performs the bit flip attack on AES-128-CTR and returns
;; true if it worked
(define (ctr-bitflip)
  (define ATTACK #"XadminXtrue")
  (define ORIGINAL (encryption-oracle ATTACK))
  (is-admin?
   (bytes-append
    (subbytes ORIGINAL 0 32) ; first 2 blocks untouched
    (convert-char #\X #\; (bytes-ref ORIGINAL 32)) ; change X to ;
    (subbytes ORIGINAL 33 38) ; keep the middle
    (convert-char #\X #\= (bytes-ref ORIGINAL 38)) ; change X to =
    (subbytes ORIGINAL 39)))) ; leave the rest alone

; convert-char : char char integer -> bytes
;; change a to b from c by XORing all three
(define (convert-char a b c)
  (bytes
   (bitwise-xor
    (char->integer a)
    (char->integer b)
    c)))


(module+ test
  (require rackunit)
  (check-true (ctr-bitflip)))

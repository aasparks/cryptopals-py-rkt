#lang racket

(require racket/random
         "../aes/aes.rkt"
         "../set1/c2.rkt"
         "c9.rkt")

; Challenge 16
;; CBC Bitflipping Attacks

(define KEY (crypto-random-bytes 16))
(define PRE #"comment1=cooking%20MCs;userdata=")
(define POST #";comment2=%20like%20a%20pound%20of%20bacon")

;; Encryption function
(define (encryption-oracle txt)
  (aes-128-cbc-encrypt
   (pkcs7-pad
    (bytes-append
     PRE
     (string->bytes/utf-8
      (string-replace
       (bytes->string/utf-8 txt)
       #rx"[;=]+"
       ""))
     POST))
   KEY
   (make-bytes 16 0)))

;; Decryption function
(define (is-admin? ct)
  (string-contains?
   (bytes->string/latin-1 ; because the block gets scrambled, it isn't a well-formed utf-8
    (pkcs7-unpad
     (aes-128-cbc-decrypt
      ct KEY (make-bytes 16 0))))
   ";admin=true;"))

#|
   If you've written the first function properly, it should
   not be possible to provide user input to it that will
   generate the string the second function is looking for.
   We'll have to break the crypto to do that.

   Instead, modify the ciphertext (without knowledge of
   the AES key) to accomplish this.

   You're relying on the fact that in CBC mode,
   a 1-bit error in a ciphertext block:
      - Completely scrambles the block the error occurs in
      - Produces the identical 1-bit error(/edit) in the next ciphertext block.
|#

;; Easy peasy

;; 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
;; comment1=cooking %20MCs;userdata= XadminXtrueX;com ...
;; They block-aligned it for us <3
(define (cbc-bitflip)
  (let* ([good-output (encryption-oracle #"XadminXtrueX")])
    (is-admin?
     (bytes-append
      (get-block good-output 0)
      (attack-block (get-block good-output 1))
      (subbytes good-output 32 (bytes-length good-output))))))

;; Attacking this block is easy. Just xor what we have with
;; what we want
(define (attack-block block)
  (bytes-append
   (xorstrs (xorstrs (subbytes block 0 12) #";admin=true;") #"XadminXtrueX")
   (subbytes block 12 (bytes-length block))))

(module+ test
  (require rackunit)

  (check-true (cbc-bitflip)))







#lang racket

; Challenge 16
;; CBC Bitflipping Attacks

(require racket/random
         "../aes/aes.rkt"
         "../set1/c2.rkt"
         "c9.rkt")

#|
   Generate a random AES key.
   Combine your padding code and CBC code to write two function.

   The first function should take an arbitrary input string,
   prepend the string
     "comment1=cooking%20MCs;userdata="
   ...and append the string
     ";comment2=%20like%20a%20pound%20of%20bacon"
   The function should quote out the ';' and '=' characters.
   The function should then pad out the input to the 16-byte
   AES block length and encrypt it under the random AES key.
|#

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
  (aes-128-cbc-encrypt (pkcs7-pad input)
                       KEY
                       (make-bytes 16 0)))

#|
   The second function should decrypt the string and look
   for the characters ";admin=true;".
   Return true or false based on whether the string exists.
|#

; is-admin? : bytes -> boolean
;; Decryption function
;; Determines if the decrypted cookie contains an admin profile
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
; cbc-bitflip : void -> bytes
;; does the CBC bitflipping attack
(define (cbc-bitflip)
  (define good-output (encryption-oracle #"XadminXtrueX"))
  (is-admin?
   (bytes-append
    (get-block good-output 0)
    (attack-block (get-block good-output 1))
    (subbytes good-output 32 (bytes-length good-output)))))

;; Attacking this block is easy. Just xor what we have with
;; what we want
; attack-block : bytes -> bytes
;; modifies the current block so the subsequent block will
;; contain the values we want when decrypted
(define (attack-block block)
  (bytes-append
   (xorstrs (xorstrs (subbytes block 0 12) #";admin=true;") #"XadminXtrueX")
   (subbytes block 12 (bytes-length block))))

(module+ test
  (require rackunit)

  (check-true (cbc-bitflip)))







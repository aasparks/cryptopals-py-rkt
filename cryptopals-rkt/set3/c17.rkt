#lang racket/base

; Challenge 17
;; The CBC padding oracle

(require racket/random
         racket/list
         "../util/aes.rkt"
         "../util/pkcs7.rkt"
         "../util/conversions.rkt")

#|
   This is the best-known attack on modern block-cipher cryptography.

   Combine your padding code and your CBC code
   to write two functions.

   The first function should select at random one
   of the following strings, generate a random AES
   key (and save it), pad the string, and CBC
   encrypt it under that key.

   The second function should consume the ciphertext produced by
   the first function, decrypt it, check its padding, and return
   true or false depending on whether the padding is valid.

   It turns out it's possible to decrypt the ciphertexts provided
   by the first function.

   The decryption here depends on a side-channel leak by the
   decryption function. The leak is the error message that the
   padding is valid or not.

   You can find 100 web pages on how this attack works, so I won't
   re-exlain it. What I'll say is this:

   The fundamental insight behind this attack is that the byte
   01h is valid padding, and occur in 1/256 trails of "randomized"
   plaintexts produced by decrypting a tampered ciphertext.

   02h is isolation is not valid padding.
   02h02h is valid padding, but is much less likely to occur randomly.
   03h03h03h is even less likely.

   So you can assume that if you corrupt a decryption AND it had valid
   padding, you know what the padding byte is.

   It is easy to get tripped up on the fact that CBC plaintexts are
   "padded". Padding oracles have nothing to do with the actual
   padding on a CBC plaintext. It's an attack that targets a specific
   bit of code that handles decryption. You can mount a padding oracle
   on any CBC block, whether it's padded or not.
|#

(define KEY (crypto-random-bytes 16))
(define IV (crypto-random-bytes 16))
(define STRS (vector-immutable
              #"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
              #"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
              #"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
              #"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
              #"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
              #"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
              #"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
              #"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
              #"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
              #"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"))

; encryption-oracle : void -> bytes
;; encrypts a random string under CBC
(define (encryption-oracle)
  (bytes-append
   IV
   (aes-128-encrypt
    (pkcs7-pad (base64->ascii (random-ref STRS)))
    KEY IV #:mode 'cbc)))

; decryption-oracle : bytes -> boolean
;; determines if the padding is valid for the given ciphertext
(define (decryption-oracle ct)
  (with-handlers ([exn:fail? (λ (v) #false)])
      (begin
        (pkcs7-unpad
         (aes-128-decrypt ct KEY IV #:mode 'cbc))
        #true)))

; cbc-padding-attack : bytes -> bytes
;; does the padding oracle attack
;; fold turns out to be the most useful function here
;; just iterate through the blocks from right to left,
;; appending the result
(define (cbc-padding-attack txt)
  (pkcs7-unpad
   (foldr
    (λ (i plaintext)
      (bytes-append (attack-block txt i)
                    plaintext))
    #""
    (range 1 (/ (bytes-length txt) 16)))))

; attack-block : bytes integer -> bytes
;; uses the padding attack for one block of the ciphertext
(define (attack-block txt block-num)
  (foldr
   (λ (byte-num plaintext)
     (bytes-append
      (attack-byte
       (get-block txt block-num)
       (get-block txt (sub1 block-num))
       byte-num
       plaintext)
      plaintext))
   #"" 
   (range 16)))

; attack-byte : bytes bytes integer bytes -> bytes
;; recursively try each byte until we find what we want
(define (attack-byte block prev-block byte-num plaintext)
  (try-attack-byte block prev-block byte-num plaintext 1))

; try-attack-byte bytes bytes integer bytes byte -> bytes
;; throw error if we can't find the byte. try to decrypt or recurse
(define (try-attack-byte block prev-block byte-num plaintext guess)
  (cond
    [(= 255 guess) (error "not found")]
    [(decryption-oracle
      (build-attack block prev-block byte-num plaintext guess))
     (bytes guess)]
    [else (try-attack-byte block prev-block byte-num plaintext (add1 guess))]))


;; here's the magic. read my python solution to try and understand what
;; is happening here.

; build-attack : bytes bytes integer bytes integer -> bytes
;; build's the block we are using to find the byte we want
(define (build-attack block prev-block byte-num plaintext i)
  ;; knownxor is the value of what we already know but set so that
  ;; the padding will always be what we want
  ;;  ex: \x02 or \x03\x03
  ;; so that the byte we are trying to find will be the missing piece
  (define knownxor
    (if (zero? (bytes-length plaintext))
        #""
        (xorstrs
         (make-bytes (bytes-length plaintext)
                     (- 16 byte-num))
         (xorstrs plaintext
                  (subbytes
                   prev-block
                   (- (bytes-length prev-block)
                      (bytes-length plaintext)))))))
  ;; build the attack here. we fill with 0's, add in our guess byte,
  ;; add in the knownxor from above if it exists, and then the block
  ;; we are trying to decrypt
  (bytes-append (make-bytes byte-num 0)
                (bytes (bitwise-xor (bitwise-xor i
                                                 (- 16 byte-num))
                                    (bytes-ref prev-block byte-num)))
                knownxor
                block))

(module+ test
  (require rackunit
           "../util/test.rkt")
  (random-seed 0)
  (define expected #"000003Cooking MC's like a pound of bacon")
  
  (time-test
   (test-suite
    "Challenge 17"
    (check-equal? (cbc-padding-attack (encryption-oracle))
                  expected))))

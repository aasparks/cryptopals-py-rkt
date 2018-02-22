#lang racket

(require racket/random
         "../aes/aes.rkt"
         "../set2/c9.rkt")

; Challenge 17
;; The CBC padding oracle

#|
  Combine your padding code and your CBC code
  to write two functions.
  The first function should select at random one
  of the following strings, generate a random AES
  key (and save it), pad the string, and CBC
  encrypt it under that key.
|#

(define KEY (crypto-random-bytes 16))
(define IV (make-bytes 16 0))
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

; encrypts a random string under CBC
(define (encryption-oracle)
  (aes-128-cbc-encrypt
   (pkcs7-pad (random-ref STRS))
   KEY
   IV))

#|
  The second function should consume the ciphertext produced by
  the first function, decrypt it, check its padding, and return
  true or false depending on whether the padding is valid.
|#
(define (decryption-oracle ct)
  (with-handlers ([exn:fail? (λ (v) #f)])
      (begin
        (pkcs7-unpad
         (aes-128-cbc-decrypt ct KEY IV))
        #true)))


;; The Wikipedia page is super helpful for understand this.
;; https://en.wikipedia.org/wiki/Padding_oracle_attack
;; It works a lot like the attack on ECB
(define (cbc-padding-attack txt)
  (cbc-padding-attack-block txt (/ (bytes-length txt) 16)))

(define (cbc-padding-attack-block txt block)
  (if (zero? block)
      #""
      (bytes-append (cbc-padding-attack-block txt (sub1 block))
                    #;(attack-block txt block))))

(define (crack-byte prev-block block)
  )

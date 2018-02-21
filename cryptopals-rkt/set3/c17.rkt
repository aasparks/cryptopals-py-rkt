#lang racket

(require racket/random
         "../aes/aes.rkt")

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

(define (encryption-oracle)
  (aes-128-cbc-encrypt
   (pkcs7-pad (random-ref STRS))
   KEY
   IV))
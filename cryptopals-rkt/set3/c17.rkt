#lang racket

(require racket/random
         "../aes/aes.rkt"
         "../set2/c9.rkt"
         "../set1/c1.rkt"
         "../set1/c2.rkt")

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

; encrypts a random string under CBC
(define (encryption-oracle)
  (bytes-append
   IV
   (aes-128-cbc-encrypt
    (pkcs7-pad
     (base64->ascii (random-ref STRS)))
    KEY
    IV)))

#|
  The second function should consume the ciphertext produced by
  the first function, decrypt it, check its padding, and return
  true or false depending on whether the padding is valid.
|#
(define (decryption-oracle ct)
  (with-handlers ([exn:fail? (λ (v) #false)])
      (begin
        (pkcs7-unpad
         (aes-128-cbc-decrypt ct KEY IV))
        #true)))

;; printf and return a value
(define (debug-printf value [preface ""] #:to-hex [to-hex #f])
  (begin
    (printf "~v ~v\n"
            preface
            (if to-hex
                (ascii->hex value)
                value))
    value))

;; fold turns out to be the most useful function here
;; just iterate through the blocks from right to left,
;; appending the result
(define (cbc-padding-attack txt)
  (pkcs7-unpad
   (foldl
    (λ (i plaintext)
      (bytes-append (attack-block txt i)
                    plaintext))
    #""
    (reverse (range 1 (/ (bytes-length txt) 16))))))

;; fold again for each byte
(define (attack-block txt block-num)
  (foldl
   (λ (byte-num plaintext)
     (bytes-append
      (attack-byte
       (get-block txt block-num)
       (get-block txt (sub1 block-num))
       byte-num
       plaintext)
      plaintext))
   #"" 
   (reverse (range 16))))

;; recursively try each byte until we find what we want
(define (attack-byte block prev-block byte-num plaintext)
  (try-attack-byte block prev-block byte-num plaintext 1))

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
(define (build-attack block prev-block byte-num plaintext i)
  ;; knownxor is the value of what we already know but set so that
  ;; the padding will always be what we want
  ;;  ex: \x02 or \x03\x03
  ;; so that the byte we are trying to find will be the missing piece
  (let ([knownxor (if (zero? (bytes-length plaintext))
                      #""
                      (xorstrs
                       (make-bytes (bytes-length plaintext)
                                   (- 16 byte-num))
                       (xorstrs plaintext
                                (subbytes prev-block
                                          (- (bytes-length prev-block)
                                             (bytes-length plaintext))))))])
    ;; build the attack here. we fill with 0's, add in our guess byte,
    ;; add in the knownxor from above if it exists, and then the block
    ;; we are trying to decrypt
    (bytes-append (make-bytes byte-num 0)
                  (bytes (bitwise-xor (bitwise-xor i
                                                   (- 16 byte-num))
                                      (bytes-ref prev-block byte-num)))
                  knownxor
                  block)))

(module+ test
  (cbc-padding-attack (encryption-oracle)))

#lang racket

(require racket/random
         "../aes/aes.rkt"
         "c9.rkt"
         "../set1/c1.rkt")

; Challenge 14
;; Byte-at-a-time ECB decryption (Harder)

#|
  Take your oracle from challenge 12. Now generate
  a random count of random bytes and prepend this string
  to every plaintext. You are now doing:
     AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
  Same goal: decrypt the target-bytes
|#

(define KEY (crypto-random-bytes 16))
(define PREFIX (crypto-random-bytes (random 100)))
(define SUFFIX (bytes-append
                #"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSBy"
                #"YWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g"
                #"YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5"
                #"IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQg"
                #"eW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))

; encryption-oracle : bytes -> bytes
;; encrypts the given text under a secret key with
;; a secret random prefix and a suffix
(define (encryption-oracle txt)
  (aes-128-ecb-encrypt
   (pkcs7-pad
    (bytes-append PREFIX
                  txt
                  (base64->ascii SUFFIX)))
   KEY))


;; Since the prefix is constant, this is pretty much the same
;; as last time, but we need to find the prefix first.
;; How?

;; Sending with ''    : XXXX XXTH ESEC RET1
;; Sending with 'A'   : XXXX XXAT HESE CRET 4444
;;;; Right away we can see that the prefix ends in the second block
;;;; because that's the block where the data is changed.
;; How do we figure out exactly which byte?
;; Sending with 'AA'  : XXXX XXAA THES ECRE T333
;; Sending with 'AAA' : XXXX XXAA ATHE SECR ET22
;;;; Ok now we see that we reached the end of the block
;;;; because block 2 was the same for these two inputs.
;; So the last byte of prefix is where we are minus how much we put in
;; size = start-len + (blocksize - (len(controlled-bytes)-1))
;; size = 4 + 4 - 3 + 1 = 6

; get-prefix-info : void -> (listof integer integer)
;; returns information about the prefix
;;  1. the length of the prefix
;;  2. the extra bytes needed for block alignment
(define (get-prefix-info)
  (define original (encryption-oracle #""))
  (define prefix-block
    (find-prefix-block original
                       (encryption-oracle #"A")))
  (define len (get-prefix-info-recur 0 prefix-block))
  (list
   (+ (* prefix-block 16)
      16
      (- len))
   (modulo len 16)))

; get-prefix-info-recur : integer bytes -> integer
;; recursively looks for the block where the prefix ends
(define (get-prefix-info-recur i prefix-block)
  (if (bytes=? (get-block
                (encryption-oracle
                 (make-bytes i 65))
                prefix-block)
               (get-block
                (encryption-oracle
                 (make-bytes (add1 i) 65))
                prefix-block))
      i
      (get-prefix-info-recur (add1 i) prefix-block)))

; get-prefix-size : void -> integer
;; returns the prefix size
(define (get-prefix-size)
  (first (get-prefix-info)))

; find-prefix-block bytes bytes -> bytes
;; Finds the location of the prefix block given the encryption of #"" and #"A"
(define (find-prefix-block original test)
  (find-prefix-block-recur original test 0))

; find-prefix-block-recur original test block
;; recursively searches for the prefix block
(define (find-prefix-block-recur original test block)
  (if (not (bytes=?
            (get-block original block)
            (get-block test block)))
      block
      (find-prefix-block-recur original test (add1 block))))

;; Step 3: craft an input block
; craft-block : integer integer -> bytes
;; craft an input block that is one byte short
(define (craft-block offset num-bytes)
  (make-bytes (sub1 (- num-bytes offset)) 65))

;; Step 4-5: find the correct value for the last byte
; decode-byte : bytes integer integer integer -> bytes
;; finds the correct value for the last unknown byte
(define (decode-byte known-bytes num-bytes prefix-len needed-extra)
  (define prefix
    (craft-block (bytes-length known-bytes)
                 (+ num-bytes needed-extra)))
  (define original (encryption-oracle prefix))
  (define test-len (+ (bytes-length prefix)
                      (bytes-length known-bytes)
                      prefix-len
                      1))
  (try-all-bytes prefix known-bytes original test-len 0))

; try-all-bytes : bytes bytes bytes integer integer -> bytes
;; recursively try all bytes from 255 down to 0,
;; returning the one that gives us the correct value
(define (try-all-bytes prefix known-bytes original test-len i)
  (cond
    [(> i 255) #false]
    [(test-byte
      (bytes-append prefix known-bytes (bytes i))
      original
      test-len) (bytes i)]
    [else (try-all-bytes
           prefix known-bytes original test-len (add1 i))]))

; test-byte : bytes bytes integer -> boolean
;; determine if this byte is the matching one
(define (test-byte test-input original test-len)
  (define test-output (encryption-oracle test-input))
  (equal? (subbytes test-output 0 test-len)
          (subbytes original 0 test-len)))

;; Step 6: repeat
; decode-secret : void -> bytes
;; decode the entire secret message one byte at a time
(define (decode-secret)
  (define prefix-info (get-prefix-info))
  (define num-bytes (- (bytes-length
                        (encryption-oracle
                         (make-bytes (second prefix-info) 65)))
                       (first prefix-info)
                       (second prefix-info)))
  (decode-secret-recur #""
                       num-bytes
                       (first prefix-info)
                       (second prefix-info)))

; decode-secret-recur : bytes integer integer integer -> bytes
;; recursively decode a byte until we can't find one
(define (decode-secret-recur known num-bytes prefix-len needed-extra)
  (define found-byte
    (decode-byte known num-bytes prefix-len needed-extra))
  (if found-byte
      (decode-secret-recur
       (bytes-append known found-byte)
       num-bytes
       prefix-len
       needed-extra)
      known))


(module+ test
  (require rackunit)
  (check-equal? (get-prefix-size)
                (bytes-length PREFIX))
  (check-equal? (pkcs7-unpad (decode-secret))
                (base64->ascii SUFFIX)))
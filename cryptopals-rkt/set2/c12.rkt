#lang racket/base

; Challenge 12
;; Byte-at-a-time ECB decryption (Simple)

(require racket/random
         "../util/conversions.rkt"
         "../util/aes.rkt"
         "../util/pkcs7.rkt"
         "../set1/c8.rkt")

#|
   Copy your oracle function to a new function that encrypts buffers under
   ECB mode using a consistent but unknown key.

   Now take that same function and have it append to the plaintext,
   BEFORE ENCRYPTING, the following string:
     Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
     YnkK

   Base64 decode the string before appending it.
   What you have now is a function that produces:
     AES-128-ECB(your-string || unknown-string, random-key)

   It turns out: you can decrypt "unknown-string" with repeated calls
   to the oracle function!
   Here's roughly how:
     1. Feed identical bytes of your-string to the function 1 at a time
        to discover the block size.
     2. Detect that the function is using ECB. You know this, but do it anyway.
     3. Knowing the block size, craft an input block that is exactly 1 byte
        short. Think about what the oracle function is going to put in the
        last byte position.
     4. Make a dictionary of every possible last byte by feeding different
        strings to the oracle; for instance "AA", "AB", "AC", remember
        the first block of each invocation.
     5. Match the output of the one-byte-short input to one of the entries in your dictionary.
        You've now discovered the first byte of unknown-string.
     6. Repeat for the next byte
|#

(define KEY (crypto-random-bytes 16))
(define POSTFIX (base64->ascii
                (bytes-append
                 #"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                 #"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                 #"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                 #"YnkK")))

; encryption-oracle : bytes -> bytes
;; encrypts the text with AES-128-ECB with unknown key
(define (encryption-oracle txt)
  (aes-128-encrypt (pkcs7-pad (bytes-append txt POSTFIX)) KEY))

; let's just go ahead and define this
(define NUM-BYTES (bytes-length (encryption-oracle #"")))

;; Step 1: find the block size
; get-blocksize : void -> integer
;; finds the blocksize by feeding the oracle bytes until it increases in
;; size (the increase will be 1 blocksize)
(define (get-blocksize)
  (get-blocksize-recur NUM-BYTES #"A"))

; get-blocksize-recur : integer bytes -> integer
; recursively add a byte to input until a new block is created and
; return the blocksize
(define (get-blocksize-recur orig-length input)
  (define new-length (bytes-length (encryption-oracle input)))
  (if (< orig-length new-length)
      (- new-length orig-length)
      (get-blocksize-recur orig-length (bytes-append input #"A"))))

;; Let's assign it here
(define BLOCKSIZE (get-blocksize))

;; Step 2: Detect that the function is using ECB
;; We wrote this for challenge 8
(unless (is-ecb? (make-bytes 65 (* BLOCKSIZE 2)))
  (error "oracle is not using ECB"))

;; Step 3: craft an input block
; craft-block : integer -> bytes
;; craft an input block that is one byte short
(define (craft-block offset)
  (make-bytes (sub1 (- NUM-BYTES offset)) 65))

;; Step 4-5: find the correct value for the last byte
; decode-byte : bytes -> bytes
(define (decode-byte known-bytes)
  (define prefix (craft-block (bytes-length known-bytes)))
  (define original (encryption-oracle prefix))
  (define test-len (+ (bytes-length prefix)
                      (bytes-length known-bytes)
                      1))
  (try-all-bytes prefix known-bytes original test-len 0))

; try-all-bytes : bytes bytes bytes integer integer -> bytes
;; recursively try all bytes from 0 to 255,
;; returning the one that gives us the correct value
(define (try-all-bytes prefix known-bytes original test-len i)
  (cond
    [(> i 127) #false] ; didn't find the byte
    [(test-byte
      (bytes-append prefix known-bytes (bytes i))
      original
      test-len)
     (bytes i)] ; found the byte
    [else
     (try-all-bytes prefix known-bytes original test-len (add1 i))])) ; keep looking

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
  (decode-secret-recur #""))

;; decode-secret-recur : bytes -> bytes
; recursively decode a byte until we can't find one
(define (decode-secret-recur known)
  (define found-byte (decode-byte known))
  (if found-byte
      (decode-secret-recur (bytes-append known found-byte))
      known))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (check-equal? (get-blocksize) 16)
  ; NOTE: interestingly, this is SUPER SUPER slow.
  ; The python solution is almost immediate. Why?
  (define challenge-12
    (test-suite
     "Challenge 12"
     (check-equal? (decode-secret)
                   (bytes-append
                    #"Rollin' in my 5.0\n"
                    #"With my rag-top down so my hair can blow\n"
                    #"The girlies on standby waving just to say hi\n"
                    #"Did you stop? No, I just drove by\n\1"))))
  (time-test challenge-12))

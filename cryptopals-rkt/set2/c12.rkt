#lang racket

(require "../aes/aes.rkt"
         racket/random
         "c9.rkt"
         "../set1/c1.rkt"
         "../set1/c8.rkt")

; Challenge 12
;; Byte-at-a-time ECB decryption (Simple)

#|
 Copy your oracle function to a new function that encrypts buffers under
 ECB mode using a consistent but unknown key
|#
; Encrypts using an unknown mode with random
; data inserted
(define KEY (crypto-random-bytes 16))
(define SUFFIX #"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
(define (encryption-oracle txt)
  (aes-128-ecb-encrypt (pkcs7-pad (bytes-append txt (base64->ascii SUFFIX)))
                       KEY))

; let's just go ahead and define this
(define NUM-BYTES (bytes-length (encryption-oracle #"")))

#|
 It turns out: you can decrypt "unknown-string" with repeated calls
 to the oracle function!
 Here's roughly how:
    1. Feed identical bytes of your-string to the function 1 at a time to discover the block size.
    2. Detect that the function is using ECB. You know this, but do it anyway.
    3. Knowing the block size, craft an input block that is exactly 1 byte short. Think about what
       the oracle function is going to put in the last byte position.
    4. Make a dictionary of every possible last byte by feeding different strings to the oracle;
       for instance "AA", "AB", "AC", remember the first block of each invocation.
    5. Match the output of the one-byte-short input to one of the entries in your dictionary.
       You've now discovered the first byte of unknown-string.
    6. Repeat for the next byte
|#

;; Step 1: find the block size
;; We do this by increasing our input until the block size increases.
;; Because of padding, it will increase by exactly BLOCKSIZE.
(define (get-blocksize)
  (get-blocksize-recur NUM-BYTES #"A"))
; recursively add a byte to input until a new block is created and
; return the blocksize
(define (get-blocksize-recur orig-length input)
  (let ([new-length (bytes-length (encryption-oracle input))])
    (if (< orig-length new-length)
        (- new-length orig-length)
        (get-blocksize-recur orig-length (bytes-append input #"A")))))

;; Let's assign it here
(define BLOCKSIZE (get-blocksize))

;; Step 2: Detect that the function is using ECB
;; We wrote this for challenge 8
(unless (is-ecb? (make-bytes 65 (* BLOCKSIZE 2)))
  (error "oracle is not using ECB"))

;; Step 3: craft an input block
(define (craft-block offset)
  (make-bytes (sub1 (- NUM-BYTES offset)) 65))

;; Step 4-5: find the correct value for the last byte
(define (decode-byte known-bytes)
  (let* ([prefix (craft-block (bytes-length known-bytes))]
         [original (encryption-oracle prefix)]
         [test-len (+ (bytes-length prefix)
                      (bytes-length known-bytes)
                      1)])
    #;(println known-bytes)
    (try-all-bytes prefix known-bytes original test-len 0)))

;; recursively try all bytes from 255 down to 0,
;; returning the one that gives us the correct value
(define (try-all-bytes prefix known-bytes original test-len i)
  (if (> i 255)
      #false
      (if (test-byte (bytes-append prefix known-bytes (bytes i)) original test-len)
          (bytes i)
          (try-all-bytes prefix known-bytes original test-len (add1 i)))))

;; determine if this byte is the matching one
(define (test-byte test-input original test-len)
  (let ([test-output (encryption-oracle test-input)])
    (equal? (subbytes test-output 0 test-len)
            (subbytes original 0 test-len))))

;; Step 6: repeat
(define (decode-secret)
  (decode-secret-recur #""))

; recursively decode a byte until we can't find one
(define (decode-secret-recur known)
  (let ([found-byte (decode-byte known)])
    (if found-byte
        (decode-secret-recur (bytes-append known found-byte))
        known)))

(module+ test
  (require rackunit)

  (check-equal? (get-blocksize) 16)
  ; NOTE: interestingly, this is SUPER SUPER slow.
  ; The python solution is almost immediate. Why?
  (decode-secret))

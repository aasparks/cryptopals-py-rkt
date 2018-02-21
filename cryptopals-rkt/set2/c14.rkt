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
(define SUFFIX #"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
(define (encryption-oracle txt)
  (aes-128-ecb-encrypt (pkcs7-pad (bytes-append PREFIX txt (base64->ascii SUFFIX)))
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

; Determines the size of the prefix
(define (get-prefix-info)
  (let* ([original (encryption-oracle #"")]
         [prefix-block (find-prefix-block original (encryption-oracle #"A"))]
         [len (get-prefix-info-recur 0 prefix-block)])
    (cons (+ (* prefix-block 16) 16 (- len))
          (modulo len 16))))

(define (get-prefix-info-recur i prefix-block)
  (if (bytes=? (get-block (encryption-oracle (make-bytes i 65)) prefix-block)
               (get-block (encryption-oracle (make-bytes (add1 i) 65)) prefix-block))
      i
      (get-prefix-info-recur (add1 i) prefix-block)))

(define (get-prefix-size)
  (car (get-prefix-info)))

; Finds the location of the prefix block given the encryption of #"" and #"A"
(define (find-prefix-block original test)
  (find-prefix-block-recur original test 0))

(define (find-prefix-block-recur original test block)
  (if (not (bytes=? (get-block original block) (get-block test block)))
      block
      (find-prefix-block-recur original test (add1 block))))

;; Step 3: craft an input block
(define (craft-block offset num-bytes)
  (make-bytes (sub1 (- num-bytes offset)) 65))

;; Step 4-5: find the correct value for the last byte
(define (decode-byte known-bytes num-bytes prefix-len needed-extra)
  (let* ([prefix (craft-block (bytes-length known-bytes) (+ num-bytes needed-extra))]
         [original (encryption-oracle prefix)]
         [test-len (+ (bytes-length prefix)
                      (bytes-length known-bytes)
                      prefix-len
                      1)])
    ;(println known-bytes)
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
  (let* ([prefix-info (get-prefix-info)]
        [num-bytes (- (bytes-length (encryption-oracle (make-bytes (cdr prefix-info) 65)))
                      (car prefix-info)
                      (cdr prefix-info))])
   (decode-secret-recur #"" num-bytes (car prefix-info) (cdr prefix-info))))

; recursively decode a byte until we can't find one
(define (decode-secret-recur known num-bytes prefix-len needed-extra)
  (let ([found-byte (decode-byte known num-bytes prefix-len needed-extra)])
    (if found-byte
        (decode-secret-recur (bytes-append known found-byte) num-bytes prefix-len needed-extra)
        known)))


(module+ test
  (require rackunit)
  (printf "Prefix len: ~v\n" (bytes-length PREFIX))
  (check-equal? (get-prefix-size)
                (bytes-length PREFIX))
  (decode-secret))
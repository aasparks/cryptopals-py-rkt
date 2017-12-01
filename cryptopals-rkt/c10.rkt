#lang racket

; Challenge 10
;; Implement CBC Mode
(require "c9.rkt"
         "aes/aes.rkt"
         "c1.rkt")
;;; Okay so I already did this when I implemented AES
;;; for these challenges. So CBC is done but let's just
;;; check with a simple test and of course decrypt the
;;; file for the challenge.
(define test-key #"YELLOW SUBMARINE")
(define test-iv (make-bytes 16 0))

;; opens the file and decrypts it
(define (main)
  (bytes->string/utf-8 (aes-128-cbc-decrypt (base64->ascii (file->bytes "10.txt"))
                                            test-key
                                            test-iv)))




(module+ test
  (require rackunit)
  (define test-pt (pkcs7-pad #"Who lives in a pineapple under the sea?"))
  (define test-ct (aes-128-cbc-encrypt test-pt test-key test-iv))
  (check-equal? test-pt (aes-128-cbc-decrypt test-ct test-key test-iv))
  (printf (main))
  )
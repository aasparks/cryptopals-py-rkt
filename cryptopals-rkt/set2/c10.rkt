#lang racket

; Challenge 10
;; Implement CBC Mode
(require "c9.rkt"
         "../aes/aes.rkt"
         "../set1/c1.rkt")

#|
   CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
   messages, desipite the fact that a block cipher natively only transforms
   individual blocks.

   In CBC mode, each ciphertext block is added to the next plaintext block
   before the next call to the cipher core.

   The first plaintext block, which has no associated previous ciphertext block,
   is added to a "fake 0th ciphertext block" called the initialization vector,
   or IV.

   Implement CBC mode by hand by taking the ECB function you wrote earlier, making
   it encrypt instead of decrypt, and using your XOR function from the previous
   exercise to combine them.

   The file here is intelligible when CBC decrypted against "YELLOW SUBMARINE"
   with an IV of all ASCII 0.
|#

;;; Okay so I already did this when I implemented AES
;;; for these challenges. So CBC is done but let's just
;;; check with a simple test and of course decrypt the
;;; file for the challenge.
(define test-key #"YELLOW SUBMARINE")
(define test-iv (make-bytes 16 0))

;; opens the file and decrypts it
(define (main)
  (aes-128-cbc-decrypt
   (base64->ascii
    (file->bytes "../../testdata/10.txt"))
   test-key
   test-iv))

(module+ test
  (require rackunit)

  (define DEBUG #false)
  (define test-pt (pkcs7-pad #"Who lives in a pineapple under the sea?"))
  (define test-ct (aes-128-cbc-encrypt test-pt test-key test-iv))
  (check-equal? test-pt (aes-128-cbc-decrypt test-ct test-key test-iv))
  (when DEBUG
    (printf "~v\n" (pkcs7-unpad (main)))))
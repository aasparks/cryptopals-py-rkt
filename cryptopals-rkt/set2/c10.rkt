#lang racket/base

; Challenge 10
;; Implement CBC Mode

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
(module+ test
  (require rackunit
           racket/file
           "../util/test.rkt"
           "../util/aes.rkt"
           "../util/conversions.rkt")
  (define DEBUG #true)
  (define key #"YELLOW SUBMARINE")
  (define iv (make-bytes 16 0))
  (define ct (base64->ascii (file->bytes "../../testdata/10.txt")))

  (define result (aes-128-decrypt ct key iv #:mode 'cbc))

  ; same as with ECB mode, this is a bogus test but I want to see how
  ; long it takes.
  (define challenge-10
    (test-suite
     "Challenge 10"
     (check-equal? (aes-128-decrypt ct key iv #:mode 'cbc)
                             result)))
  (time-test challenge-10))
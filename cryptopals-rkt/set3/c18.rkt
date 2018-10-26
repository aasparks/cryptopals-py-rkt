#lang racket

; Challenge 18
;; Implement CTR, The Stream Cipher Mode

#|
   The string:
      L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
   ...decrypts to something approximating English in CTR mode, which is an
   AES block cipher mode that turns AES into a stream cipher, with the
  following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)

   CTR mode is very simple.

   Instead of encrypting the plaintext, CTR mode encrypts a
   running counter, producing a 16 byte block of keystream,
   which is XOR'd against the plaintext.

   For instance, for the first 16 bytes of a message with
   these parameters:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
   ...for the next 16 bytes:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
   ...and then:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

   CTR mode does not require padding; when you run out of plaintext,
   you just stop XOR'ing keystream and stop generating keystream.

   Decryption is identical to encryption. Generate the same keystream,
   XOR, and recover the plaintext.

   Decrypt the string at the top of this function, then use your
   CTR function to encrypt and decrypt other things.
|#

;; This is added to my AES implementation
;; Let's just see the result

(module+ test
  (require "../util/aes.rkt"
           "../util/conversions.rkt"
           rackunit
           "../util/test.rkt")
  
  (define expected #"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
  (define ctxt
    (base64->ascii
     (bytes-append #"L77na/nrFsKvynd6HzOoG7GHTLXsT"
                   #"Vu9qvY/2syLXzhPweyyMTJULu/6/k"
                   #"XX0KSvoOLSFQ==")))
  (time-test
   (test-suite
    "Challenge 18"
    (check-equal?
     (aes-128-encrypt ctxt #"YELLOW SUBMARINE" 0 #:mode 'ctr)
     expected))))
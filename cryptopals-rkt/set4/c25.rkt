#lang racket

; Challenge 25
;; Break 'random access read/write' AES CTR
(require racket/random
         "../util/conversions.rkt"
         "../util/aes.rkt")
(provide api-edit
         recover-plaintext)

#|
   Back to CTR. Encrypt the recovered plaintext from this file under CTR with
   a random key (for this exercise the key should be unknown to you, but hold on to it).

   Now, write the code that allows you to 'seek' into the ciphertext, decrypt, and
   re-encrypt with different plaintext. Expose this as a function, like
   edit(ciphertext, key, offset, newtext)

   Imagine the edit function was exposed to attackers by means of an API call
   that didn't reveal the key or the original plaintext; the attacker has the
   ciphertext and controls the offset and 'new text'.

   Recover the original plaintext.
|#
(define KEY (crypto-random-bytes 16))
(define PT (aes-128-decrypt
            (base64->ascii
             (file->bytes "../../testdata/25.txt"))
            #"YELLOW SUBMARINE"))
(define CIPHERTEXT (aes-128-encrypt PT KEY 0 #:mode 'ctr))

; edit : bytes bytes integer bytes -> bytes
;; edit ciphertext at a specific offset with new plaintext
(define (edit ct key offset new-text)
  (bytes-append
   (subbytes ct 0 offset)   ; ignore early bytes.
   (subbytes (aes-128-encrypt   ; encrypt new-text and append
              (bytes-append (make-bytes offset 0) new-text)
              key 0 #:mode 'ctr)
             offset)
   (subbytes ct (+ offset (bytes-length new-text))))) ; ignore last bytes as well

; api-edit : bytes integer bytes -> bytes
;; attacker-given function that does not expose the key
(define (api-edit ct offset new-text)
  (edit ct KEY offset new-text))

; recover-plaintext : bytes
;; recovers the plaintext from api-edit
(define (recover-plaintext)
  (api-edit CIPHERTEXT 0 CIPHERTEXT))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (time-test
   (test-suite
    "Challenge 25"
    (check-equal? PT
                  (recover-plaintext)))))
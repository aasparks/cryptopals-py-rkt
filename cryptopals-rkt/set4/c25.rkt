#lang racket

; Challenge 25
;; Break 'random access read/write' AES CTR
(require racket/random
         "../set1/c1.rkt"
         "../aes/aes.rkt")


;;; Back to CTR. Encrypt the recovered plaintext from this file under CTR with
;;; a random key (for this exercise the key should be unknown to you, but hold on to it).
(define KEY (crypto-random-bytes 16))
(define PT (aes-128-ecb-decrypt
            (base64->ascii
             (file->bytes "../../testdata/25.txt"
                          #:mode 'text))
            #"YELLOW SUBMARINE"))

(define CIPHERTEXT (aes-128-ctr PT KEY 0))

;;; Now, write the code that allows you to 'seek' into the ciphertext, decrypt, and
;;; re-encrypt with different plaintext. Expose this as a function, like
;;; edit(ciphertext, key, offset, newtext)
(define (edit ct key offset new-text)
  (bytes-append
   (subbytes ct 0 offset)   ; ignore early bytes.
   (subbytes (aes-128-ctr   ; encrypt new-text and append
              (bytes-append ; to target bytes location.
               (make-bytes offset 0)
               new-text)
              key
              0)
             offset)
   (subbytes ct (+ offset (bytes-length new-text))) ; ignore last bytes as well
))

;;; Imagine the edit function was exposed to attackers by means of an API call
;;; that didn't reveal the key or the original plaintext; the attacker has the
;;; ciphertext and controls the offset and 'new text'.
(define (api-edit ct offset new-text)
  (edit ct KEY offset new-text))

;;; Recover the original plaintext.
(module+ test
  (require rackunit)

  (check-equal? PT
                (api-edit CIPHERTEXT 0 CIPHERTEXT)))
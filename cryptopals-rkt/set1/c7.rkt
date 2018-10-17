#lang racket

; Challenge 7
;; AES in ECB Mode

;; okay so racket has (planet vyzo/crypto)
;; but I thought I would just go ahead and
;; try to implement it myself to see if I could.
;; Turns out I could.
;; This implementation is only designed to
;; complete the challenges here.
;; It is probably much slower and less secure
;; but it was a fun challenge.
(require "../util/aes.rkt"
         "c1.rkt")

(define DEBUG #false)

#|
    The base64-encoded content in this file has been encrypted via
    AES-128 in ECB mode under the key
      "YELLOW SUBMARINE"
    (case-sensitive, without the quotes; exactly 16 characters).
    Decrypt it. You know the key, after all.
|#

(module+ test
  (define result
   (aes-128-decrypt
    (base64->ascii (file->bytes "../../testdata/7.txt" #:mode 'text))
    #"YELLOW SUBMARINE"))
  (when DEBUG
    (printf "~v\n" result)))
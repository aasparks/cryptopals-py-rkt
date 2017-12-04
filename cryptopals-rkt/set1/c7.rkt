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
(require "../aes/aes.rkt"
         "c1.rkt")

(module+ test
  (display
   (aes-128-ecb-decrypt
    (base64->ascii (file->bytes "../../testdata/7.txt" #:mode 'text))
    #"YELLOW SUBMARINE")))
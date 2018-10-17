#lang racket

; Challenge 2
;; Fixed XOR
(require "c1.rkt")
(provide xorstrs)

#|
   Write a function that takes two equal-length buffers and produces
   their XOR combination.

   If your function works properly, then when you feed it the string:
     1c0111001f010100061a024b53535009181c
   ...after hex decoding, and when XOR'd against:
     686974207468652062756c6c277320657965
   ...should produce:
     746865206b696420646f6e277420706c6179
|#

; xorstrs : bytes bytes -> bytes
; XOR two byte strings
(define (xorstrs bstr1 bstr2)
   ;; map actually works really well for this.
   ;; by declaration, the lists must be equal length
   ;; so map takes care of error checking and iteration
  (list->bytes
   (map bitwise-xor
        (bytes->list bstr1)
        (bytes->list bstr2))))

(module+ test
  (require rackunit
           "../util/test.rkt")

  ; Challenge 2 solution
  (define bstr1 (hex->ascii #"1c0111001f010100061a024b53535009181c"))
  (define bstr2 (hex->ascii #"686974207468652062756c6c277320657965"))

  (define challenge-2
    (test-suite
     "Challenge 2"
     (check-equal? (ascii->hex (xorstrs bstr1 bstr2))
                #"746865206b696420646f6e277420706c6179")))

  (time-test challenge-2))
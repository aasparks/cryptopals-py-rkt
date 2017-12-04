#lang racket

; Challenge 2
;; Fixed XOR
(require "c1.rkt")
(provide xorstrs)

; XOR two byte strings
(define (xorstrs bstr1 bstr2)
  (list->bytes
   ;; map actually works really well for this.
   ;; by declaration, the lists must be equal length
   ;; so map takes care of error checking and iteration
   (map bitwise-xor
        (bytes->list bstr1)
        (bytes->list bstr2))))

; Solution to challenge 2
(define (challenge2)
  (define bstr1 (hex->ascii #"1c0111001f010100061a024b53535009181c"))
  (define bstr2 (hex->ascii #"686974207468652062756c6c277320657965"))
  (equal? (ascii->hex (xorstrs bstr1 bstr2))
              #"746865206b696420646f6e277420706c6179"))

(module+ test
  (require rackunit)
  (define bstr1 (hex->ascii #"1c0111001f010100061a024b53535009181c"))
  (define bstr2 (hex->ascii #"686974207468652062756c6c277320657965"))
  (check-equal? (ascii->hex (xorstrs bstr1 bstr2))
                #"746865206b696420646f6e277420706c6179")
  (check-true (challenge2)))
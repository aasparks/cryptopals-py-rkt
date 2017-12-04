#lang racket
(require "c1.rkt"
         "c2.rkt"
         "c3.rkt")
; Challenge 4
;; Detect single-character XOR

;;; As with the python approach, I will just run challenge3
;;; on every line in the file
(define (challenge4)
  ;; functional enough? it runs much slower than python
  ;; but this is through the IDE so whatever.
  (first
   (sort
    (map (λ (line)
           (single-byte-xor (hex->ascii (string->bytes/utf-8 line))))
         (file->lines "../../testdata/4.txt")) 
    (λ (x y)
      (> (car x) (car y))))))

(module+ test
  (require rackunit)
  (define sol (challenge4))
  (check-equal? (xorstrs (third sol)
                         (key-extend (second sol)
                                     (bytes-length (third sol))))
                #"Now that the party is jumping\n"))
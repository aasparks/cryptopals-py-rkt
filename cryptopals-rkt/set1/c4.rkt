#lang racket
(require "c1.rkt"
         "c2.rkt"
         "c3.rkt")
; Challenge 4
;; Detect single-character XOR

#|
   One of the 60-character strings in this file has been
   encrypted by single-character XOR. Find it.
|#

;;; As with the python approach, I will just run challenge3
;;; on every line in the file
(define (challenge4)
  ;; functional enough? it runs much slower than python. Why?
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
  (display (ascii->hex (third sol)))
  (check-equal? (xorstrs (third sol)
                         (make-bytes (bytes-length (third sol))
                                     (second sol)))
                #"Now that the party is jumping\n"))
#lang racket/base

; Challenge 4
;; Detect single-character XOR

#|
   One of the 60-character strings in this file has been
   encrypted by single-character XOR. Find it.
|#
(require "../util/conversions.rkt"
         "c3.rkt"
         racket/list
         racket/file)
(provide detect-single-char-xor)

; detect-single-char-xor : string? -> bytes
;; finds the line in the given file that is single-byte xor'd.
;; Returns decrypted line
(define (detect-single-char-xor file)
  (define result
    (argmax first
            (map (λ (line)
                   (list (single-byte-xor (hex->ascii line))
                         (hex->ascii line)))
                 (file->bytes-lines file))))
  (xorstrs (second result)
           (make-bytes (bytes-length (second result)) (first result))))

(module+ test
  (require rackunit
           "../util/test.rkt")
  
  (define challenge4
    (test-suite
     "Challenge 4"
     (check-equal?
      (detect-single-char-xor "../../testdata/4.txt")
      #"Now that the party is jumping\n")))

  (time-test challenge4))
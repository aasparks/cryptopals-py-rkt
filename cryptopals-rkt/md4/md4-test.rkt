#lang racket

#| This file contains the tests for MD4 |#

(module+ test
  (require rackunit
           "../set1/c1.rkt"
           "md4.rkt")

  ; time-test : string? (any/c -> any/c) => void
  ; counts the time it takes to perform the check for each
  ; given test. This includes the time required to build the
  ; byte-strings before running (hopefully negligible), and the
  ; time for check-equal? to do what it does internally (also hopefully
  ; negligible).
  (define (time-test name f)
    (define t (current-inexact-milliseconds))
    (f)
    (printf "Test ~v completed in ~v ms\n"
            name
            (- (current-inexact-milliseconds) t)))

  ; ""
  (time-test
   "empty string"
   (λ()
     (check-equal?
      (ascii->hex (md4 #""))
      #"31d6cfe0d16ae931b73c59d7e0c089c0")))

  ; "abc"
  (time-test
   "abc"
   (λ()
     (check-equal?
      (ascii->hex (md4 #"abc"))
      #"a448017aaf21d8525fc10ae87aa6729d")))

  ; 2 blocks
  (time-test
   "2 blocks"
   (λ()
     (check-equal?
      (ascii->hex
       (md4 #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
      #"043f8582f241db351ce627e153e7f0e4")))

  ; 1 million A's
  (time-test
   "1 million A's"
   (λ()
     (check-equal?
      (ascii->hex
       (md4 (make-bytes 1000000 65)))
      #"a13f9ee75c400d8e6837bd724fb92d66")))

  (display "\nCompare results to Python results\n")
  )
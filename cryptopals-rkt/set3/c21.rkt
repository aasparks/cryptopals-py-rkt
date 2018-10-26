#lang racket/base

; Challenge 21
;; Implement the MT19937 Mersenne Twister RNG

#|
   You can get the psuedocode for this from Wikipedia.

   If you're writing in Python, Ruby, or (gah) PHP,
   your language is probably already giving you MT19937
   as "rand()"; don't use rand. Write the RNG yourself.
|#

;; This is in "util/mt19937.rkt"
;; We'll just put the tests here
(module+ test
  (require rackunit
           racket/class
           racket/file
           "../util/mt19937.rkt"
           "../util/test.rkt")
  (define mt (new MT19937% [seed 1131464071]))

  (define expected
    (for/vector ([line (file->lines "../../testdata/21.txt")])
      (string->number line)))

  (time-test
   (test-suite "Challenge 21"
               (check-equal? (for/vector ([i (in-range (vector-length expected))])
                               (send mt generate-number))
                             expected))))
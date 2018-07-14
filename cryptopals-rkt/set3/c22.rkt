#lang racket

(require "c21.rkt")

; Challenge 22
;; Crack an MT19937 seed

;;; Make sure your MT19937 accepts an integer seed value. Test it.
;;; Write a routine that performs the following operation:
;;;  - Wait a random number of seconds betweeen 40 and 1000.
;;;  - Seed the RNG with the current Unix timestamp
;;;  - Wait a random number of seconds again.
;;;  - Returns the first 32 bit output of the RNG.
;;; You get the idea. From the 32 bit output, discover the seed.
(define (get-coffee)
  (printf "Getting coffee...\n")
  (sleep (random 40 1000))
  (define t (current-seconds))
  (sleep (random 40 1000))
  (define mt (new MT19937% [seed t]))
  (printf "Using secret seed ~v\n" t)
  (send mt generate-number))

;; To find the seed, just take the current time and keep
;; trying backwards until there is a match.
(define (find-seed)
  (define output (get-coffee))
  (sub1
   (for/last ([t (in-range (current-seconds) 0 -1)]
             #:break (equal?
                      output
                      (send (new MT19937% [seed t]) generate-number)))
    t)))

(printf "Seed is ~v\n" (find-seed))
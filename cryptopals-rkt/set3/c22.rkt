#lang racket

(require "c21.rkt")

; Challenge 22
;; Crack an MT19937 seed

(define DEBUG #false)

#|
   Make sure your MT19937 accepts an integer seed value. Test it.
   Write a routine that performs the following operation:
    - Wait a random number of seconds betweeen 40 and 1000.
    - Seed the RNG with the current Unix timestamp
    - Wait a random number of seconds again.
    - Returns the first 32 bit output of the RNG.
   You get the idea. From the 32 bit output, discover the seed.
|#
; get-coffee : void -> (object . integer)
;; waits a random amount of time then returns 
(define (get-coffee)
  (printf "Getting coffee...\n")
  (sleep (random 40 1000))
  (define t (current-seconds))
  (sleep (random 40 1000))
  (define mt (new MT19937% [seed t]))
  (when DEBUG
    (printf "Using secret seed ~v\n" t))
  (list mt (send mt generate-number)))

;; To find the seed, just take the current time and keep
;; trying backwards until there is a match.
(define (find-seed num)
  (for/last ([t (in-range (current-seconds) 0 -1)]
             #:final (equal?
                      num
                      (send (new MT19937% [seed t]) generate-number)))
    t))


(module+ test
  (require rackunit)

  ; get coffee
  (define result (get-coffee))
  (define actual-mt (first result))
  (define first-num (second result))

  ; find the seed
  (define found-seed (find-seed first-num))
  (when DEBUG
    (printf "Seed is ~v\n" found-seed))

  ; run both generators forward
  (define my-mt (new MT19937% [seed found-seed]))
  (define my-first (send my-mt generate-number))

  (check-equal? my-first first-num)

  (for ([i (in-range 50)])
    (check-equal? (send my-mt generate-number)
                  (send actual-mt generate-number))))
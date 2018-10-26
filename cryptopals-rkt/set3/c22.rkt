#lang racket/base

; Challenge 22
;; Crack an MT19937 seed
(require racket/class
         "../util/mt19937.rkt")
(provide get-coffee
         find-seed)
(define DEBUG #false)

#|
   Make sure your MT19937 accepts an integer seed value. Test it.

   Write a routine that performs the following operation:
    - Wait a random number of seconds betweeen 40 and 1000.
    - Seed the RNG with the current Unix timestamp
    - Wait a random number of seconds again.
    - Returns the first 32 bit output of the RNG.

   You get the idea. Go get coffee while it runs. Or
   just simulate the passage of time, although you're
   missing some of the fun of this exercise if you do that.

   From the 32 bit RNG output, discover the seed.
|#

; get-coffee : boolean -> MT19937%
;; waits a random amount of time then returns
;; a PRNG seeded with the time. If test is true
;; it just picks a random number and substracts that
;; from the current time instead of sleeping
(define (get-coffee [test #f])
  (printf "Getting coffee...\n")
  (unless test (sleep (random 40 1000)))
  (define t (if test
                (- (current-seconds) (random 40 1000))
                (current-seconds)))
  (unless test (sleep (random 40 1000)))
  (when DEBUG
    (printf "Using secret seed ~v\n" t))
  (new MT19937% [seed t]))

;; To find the seed, just take the current time and keep
;; trying backwards until there is a match.
(define (find-seed num)
  (for/last ([t (in-range (current-seconds) 0 -1)]
             #:final (equal?
                      num
                      (send (new MT19937% [seed t]) generate-number)))
    t))


(module+ test
  (require rackunit
           "../util/test.rkt")
  ; get coffee
  (define actual-mt (get-coffee #true))
  (define first-num (send actual-mt generate-number))

  ; find the seed
  (define found-seed (find-seed first-num))
  (when DEBUG
    (printf "Seed is ~v\n" found-seed))

  ; run both generators forward
  (define my-mt (new MT19937% [seed found-seed]))
  (define my-first (send my-mt generate-number))

  (check-equal? my-first first-num)

  (time-test
   (test-suite
    "Challenge 22"
    (for ([i (in-range 50)])
      (check-equal? (send my-mt generate-number)
                    (send actual-mt generate-number))))))
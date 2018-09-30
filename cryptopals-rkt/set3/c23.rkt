#lang racket

; Challenge 23
;; Clone an MT19937 RNG from its output

#|
   The internal state of MT19937 consists of 624 32 bit integers.
   For each batch of 624 outputs, MT permutes that internal state.
   By permuting state regularly, MT19937 achievs a period of
   2^19937, which is Big.
   Each time MT19937 is tapped, an element of its internal state
   is subjected to a tempering function that diffuses bits through
   the result.
   The tempering function is invertible; you can write an untemper
   function that takes an MT19937 output and transforms it back into
   the corresponding element of the MT19937 state array.
|#

; useful constants
(define B #x9D2C5680)
(define C #xEFC60000)
(define L 18)
(define S 7)
(define T 15)
(define U 11)

; untemper : integer -> integer
;; reverses the state of a single number for MT19937
(define (untemper num)
  (un-rightshift
   (un-leftshift
    (un-leftshift
     (un-rightshift num L)
     T C)
    S B)
   U))

#|
   To invert the temper transform, apply the inverse of each of the
   operations in the temper transform in reverse order. There are two kinds
   of operations in the temper transform each applied twice; one is an XOR
   against a right-shifted value, and the other is an XOR against a left-shifted
   value AND'd with a magic number. So you'll need code to invert the "right"
   and the "left" operation.
|#
; Unbitshift functions taken from
; https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
; and ported to Racket

; un-leftshift : integer integer integer -> integer
;; reverses the MT19937 left shift operation
(define (un-leftshift value shift mask)
  (define val (box value))
  (define result (box 0))
  (for ([i (in-range 32)]
        #:break (>= (* i shift) 32))
    (define part-mask
      (arithmetic-shift (rlshift -1 (- 32 shift))
                        (* i shift)))
    (define part (bitwise-and (unbox val) part-mask))
    (set-box! val
              (bitwise-xor (unbox val)
                           (bitwise-and mask
                                        (arithmetic-shift part shift))))
    (set-box! result
              (bitwise-ior (unbox result) part)))
  (unbox result))

; un-rightshift : integer integer -> integer
;; reverses the MT19937 right shift operation
(define (un-rightshift value shift)
  (define val (box value))
  (define result (box 0))
  (for ([i (in-range 32)]
        #:break (>= (* i shift) 32))
    (define mask
      (rlshift
       (arithmetic-shift -1 (- 32 shift))
       (* i shift)))
    (define part (bitwise-and (unbox val) mask))
    (set-box! val
              (bitwise-xor (unbox val) (rlshift part shift)))
    (set-box! result (bitwise-ior (unbox result) part)))
  (unbox result))

; rlshift : integer integer -> integer
;; Racket only has arithmetic shift. This performs a logical right shift.
(define (rlshift value n)
  (arithmetic-shift (modulo value #x100000000) (- n)))

#|
   Once you have untemper working, create a new MT19937 generator, tap it for
   624 outputs, untemper each of them to recreate the state of the generator,
   and splice that state into a new instance of the MT19937 generator.
   The new spliced generator should predict the values of the original.
|#

(module+ test
  (require rackunit)
  (require "c21.rkt")
  ; create number generator
  (define mt (new MT19937% [seed 1131464071]))
  ; extract the state by untempering 624 numbers
  (define extracted-state
    (apply vector
           (map untemper
                (for/list ([i (in-range 624)])
                  (send mt generate-number)))))
  ; insert the new state into a new generator
  (define new-mt (new MT19937% [seed 0]))
  (send new-mt set-state extracted-state)
  ; check that the generators make the same numbers for the next
  ; 50 runs
  (for ([i (in-range 50)])
    (check-equal? (send mt generate-number) (send new-mt generate-number))))


























#lang racket

#| This file contains the math functions
   needed by MD4|#

(provide (all-defined-out))

;;; We first define three auxiliary functions
(define (F x y z)
  (bitwise-ior
   (bitwise-and x y)
   (bitwise-and (bitwise-not x) z)))
(define (G x y z)
  (bitwise-ior
   (bitwise-and x y)
   (bitwise-and x z)
   (bitwise-and y z)))
(define (H x y z)
  (bitwise-xor x y z))

; sum-vectors : (Listof (vector integer?)) -> (vector integer?)
(define (sum-vectors va vb)
  (vector-map (λ (a b)
                (sum32 a b))
              va
              vb))

; sum32 : integer ... -> integer
;; sums all elements modulo 32-bits
(define (sum32 . a)
  (bitwise-and (apply + a)
               #xFFFFFFFF))

; rotl : integer? integer? -> integer?
; The circular left shift operation, where x
; is a 32-bit word and n is an integer.
; Defined in FIPS 180-4 as
; ROTL(x, n) = (x >> n) || (x << 32-n)
(define (rotl x n)
  (bitwise-and
   (bitwise-ior
    (arithmetic-shift x n)
    (arithmetic-shift x (- n 32)))
   #xFFFFFFFF))
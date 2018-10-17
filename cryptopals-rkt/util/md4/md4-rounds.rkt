#lang racket

(require "md4-math.rkt")

(define DEBUG #false)

(provide (all-defined-out))

;; Okay this is where it gets tricky.
;; Each round involves A LOT of mutation.
;; How can I do this with store-passing style?
;; Basically, I don't think I can get by without
;; using mutation. The following functions are
;; not going to look pretty.

; round1 : (vector bytes?) -> (vector bytes?)
#| Let [abcd k s] denote the operation:
    a = (a + F(b,c,d) + X[k]) <<< s
|#
(define (round1 regs X)
  (when DEBUG
    (printf "~v\n" X))
  (define (round1-f a b c d k s)
    (rotl
     (sum32 a
        (F b c d)
        (vector-ref X k))
     s))
  (define-values (A B C D)
    (apply values (vector->list regs)))
  (set! A (round1-f A B C D 0 3))
  (set! D (round1-f D A B C 1 7))
  (set! C (round1-f C D A B 2 11))
  (set! B (round1-f B C D A 3 19))
  (set! A (round1-f A B C D 4 3))
  (set! D (round1-f D A B C 5 7))
  (set! C (round1-f C D A B 6 11))
  (set! B (round1-f B C D A 7 19))
  (set! A (round1-f A B C D 8 3))
  (set! D (round1-f D A B C 9 7))
  (set! C (round1-f C D A B 10 11))
  (set! B (round1-f B C D A 11 19))
  (set! A (round1-f A B C D 12 3))
  (set! D (round1-f D A B C 13 7))
  (set! C (round1-f C D A B 14 11))
  (set! B (round1-f B C D A 15 19))
  (when DEBUG
    (printf "After round1:\nA: ~x\nB: ~x\nC: ~x\nD: ~x\n"
            A B C D))
  (vector A B C D))

; round2 : (vector bytes?) -> (vector bytes?)
#| Let [abcd k s] denote the operation:
    a = (a + G(b,c,d) + X[k] + #x5A827999) <<< s
|#
(define (round2 regs X)
  (define (round2-f a b c d k s)
    (rotl
     (sum32 a
        (G b c d)
        (vector-ref X k)
        #x5A827999)
     s))
  (define-values (A B C D)
    (apply values (vector->list regs)))
  (set! A (round2-f A B C D 0 3))
  (set! D (round2-f D A B C 4 5))
  (set! C (round2-f C D A B 8 9))
  (set! B (round2-f B C D A 12 13))
  (set! A (round2-f A B C D 1 3))
  (set! D (round2-f D A B C 5 5))
  (set! C (round2-f C D A B 9 9))
  (set! B (round2-f B C D A 13 13))
  (set! A (round2-f A B C D 2 3))
  (set! D (round2-f D A B C 6 5))
  (set! C (round2-f C D A B 10 9))
  (set! B (round2-f B C D A 14 13))
  (set! A (round2-f A B C D 3 3))
  (set! D (round2-f D A B C 7 5))
  (set! C (round2-f C D A B 11 9))
  (set! B (round2-f B C D A 15 13))
  (when DEBUG
    (printf
     "After round2:\nA: ~x\nB: ~x\nC: ~x\nD: ~x\n"
     A B C D))
  (vector A B C D))

; round3 : (vector bytes?) -> (vector bytes?)
#| Let [abcd k s] denote the operation:
    a = (a + H(b,c,d) + X[k] + #x6ED9EBA1
|#
(define (round3 regs X)
  (define (round3-f a b c d k s)
    (rotl
     (sum32 a
        (H b c d)
        (vector-ref X k)
        #x6ED9EBA1)
     s))
  (define-values (A B C D)
    (apply values (vector->list regs)))
  (set! A (round3-f A B C D 0 3))
  (set! D (round3-f D A B C 8 9))
  (set! C (round3-f C D A B 4 11))
  (set! B (round3-f B C D A 12 15))
  (set! A (round3-f A B C D 2 3))
  (set! D (round3-f D A B C 10 9))
  (set! C (round3-f C D A B 6 11))
  (set! B (round3-f B C D A 14 15))
  (set! A (round3-f A B C D 1 3))
  (set! D (round3-f D A B C 9 9))
  (set! C (round3-f C D A B 5 11))
  (set! B (round3-f B C D A 13 15))
  (set! A (round3-f A B C D 3 3))
  (set! D (round3-f D A B C 11 9))
  (set! C (round3-f C D A B 7 11))
  (set! B (round3-f B C D A 15 15))
  (when DEBUG
    (printf
     "After round3:\nA: ~x\nB: ~x\nC: ~x\nD: ~x\n"
     A B C D))
  (vector A B C D))
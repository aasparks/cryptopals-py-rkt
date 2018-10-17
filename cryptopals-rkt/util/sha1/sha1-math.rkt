#lang racket

#| This file contains the math functions
   used by SHA-1
|#

(provide (all-defined-out))

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

#|
   SHA-1 uses a sequence of logical functions. Each function operates
   on three 32-bit words (x, y, and z), and produces a 32-bit word
   as output. The functions are defined as follows
     Ch(x, y, z) = (x & y) ^ (!x & z)            0  <= t <= 19
     Parity(x, y, z) = x ^ y ^ z                 20 <= t <= 39
     Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)  40 <= t <= 59
     Parity                                      60 <= t <= 79
|#
(define (ch x y z)
  (bitwise-xor
   (bitwise-and x y)
   (bitwise-and (bitwise-not x) z)))
(define (parity x y z)
  (bitwise-xor x y z))
(define (maj x y z)
  (bitwise-xor
   (bitwise-and x y)
   (bitwise-and x z)
   (bitwise-and y z)))

; split-msg : bytes? -> (listof bytes?)
; splits the message into a list of 4-byte
; blocks
(define (split-msg msg)
  (cond
    [(= 0 (bytes-length msg)) empty]
    [else (cons (subbytes msg 0 4)
                (split-msg (subbytes msg 4)))]))


; prepare-message-sched : bytes? real? -> (vector? bytes?)
; prepares the message schedule (creates the w array) by
; splitting the message block into 32-bit words and applying
; the operations described in FIPS 180-4.
(define (prepare-message-sched msg block-num)
  (define msg-block
    (list->vector
     (split-msg
      (subbytes msg
                (* block-num 64)
                (* (add1 block-num) 64)))))
  (define w (make-vector 80 0))
  (for ([i (in-range 16)])
    (vector-set!
     w
     i
     (integer-bytes->integer
      (vector-ref msg-block i)
      #f #t)))
  (for ([i (in-range 16 80)])
    (vector-set!
     w
     i
     (rotl
      (bitwise-xor
       (vector-ref w (- i 3))
       (vector-ref w (- i 8))
       (vector-ref w (- i 14))
       (vector-ref w (- i 16)))
      1)))
  w)
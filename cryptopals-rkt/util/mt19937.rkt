#lang racket/base

(require racket/class
         racket/vector
         racket/random)
(provide MT19937%)
;; I feel like a class is my best option here. I really
;; didn't want to use one but I'm not seeing a better way right
;; now.
;; If you want good documentation, refer to the  python implementation.
;; This is a direct port of my python code.

;;; Constants
(define W 32) ; word size
(define N 624) ; degree of recurrence
(define M 397) ; middle word
(define R 31) ; separation point of one word
(define A #x9908B0DF) ; coefficients of the rational normal form twist matrix
; tempering bitmasks
(define B #x9D2C5680)
(define C #xEFC60000)
(define S 7)
(define T 15)
(define U 11)
(define D #xFFFFFFFF)
(define L 18)
(define F 1812433253)

; int32 : real -> integer
;; ensures 32-bit integer
(define (int32 n)
  (bitwise-and n D))

;; MT19937
;; This is the class definition for MT19937,
;; The Mersenne Twister. It provides the public method
;; (generate-number) and must include a seed.
;; Example usage:
;;   (define mt (new MT19937% [seed 2134]))
;;   (send mt generate-number)
(define MT19937%
  (class object%
    (init [seed (integer-bytes->integer
                 (crypto-random-bytes 8)
                 #f #f)]
          [state (default-state seed)])
    (super-new)

    ; private fields
    (define current-seed seed)
    (define current-state state)
    (define index N)

    ;; initialization of mt state
    (define/private (default-state seed)
      (foldl
       (λ (i v)
         (define prev (vector-ref v i))
         (define prev-shifted (arithmetic-shift prev (- (- W 2))))
         (vector-append v
                        (vector
                         (int32 (+ (add1 i) (* F
                                        (bitwise-xor prev
                                                     prev-shifted)))))))
      (vector seed)
      (build-list N values)))

    ;; generate-number : void -> integer
    ;; generates the next number in the PRNG, calling twist when
    ;; needed.
    (define/public (generate-number)
      (when (>= index N)
        (twist))
      ; shift functions to avoid sequential set! operations
      (define (y-shift y amt)
        (bitwise-xor y (arithmetic-shift y (- amt))))
      (define (y-shift2 y mask amt)
        (bitwise-xor y (bitwise-and mask (arithmetic-shift y amt))))
      
      (define y (vector-ref current-state index))
      (set! index (add1 index))
      ;; y = y ^ (y >> self.u)
      (int32
       (y-shift
        (y-shift2
         (y-shift2
          (y-shift y U)
          B S)
         C T)
        L)))

    ;; twist
    ;; Updates the state of PRNG, as defined in the documentation for
    ;; MT19937
    (define/private (twist)
      (define first-bitmask #x80000000)
      (define last-bitmask #x7FFFFFFF)

      (for ([i (in-range 624)])
        (define idx (modulo (add1 i) 624))
        (define first-i (bitwise-and first-bitmask
                                     (vector-ref current-state i)))
        (define last-i (bitwise-and last-bitmask
                                    (vector-ref current-state idx)))
        (define t (int32 (bitwise-ior first-i last-i)))
        (define temp (if (zero? (modulo t 2))
                         (arithmetic-shift t -1)
                         (bitwise-xor A (arithmetic-shift t -1))))
        (vector-set! current-state i
                     (bitwise-xor
                      temp
                      (vector-ref current-state
                                  (modulo (+ i M)
                                          624)))))
      (set! index 0))))
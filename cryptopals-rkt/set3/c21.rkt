#lang racket

;;; Implement the MT19937 Mersenne Twister RNG
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
    (init seed)
    (super-new)

    ; private fields
    (define current-seed seed)
    (define state (make-vector N))
    (define index (box N))

    ; for c23, we need to allow the generator to accept a
    ; different state, after init.
    (define/public (set-state new-state)
      (set! state new-state))

    ;; initialization of mt state
    (vector-set! state 0 seed)

    (for ([i (in-range 1 N)])
      (define prev (vector-ref state (sub1 i)))
      (define prev-shifted (arithmetic-shift prev (- (- W 2))))
      (vector-set! state
                   i
                   (int32
                    (+ i
                       (* F
                          (bitwise-xor prev
                                       prev-shifted)))))) 

    ;; generate-number : void -> integer
    ;; generates the next number in the PRNG, calling twist when
    ;; needed.
    (define/public (generate-number)
      (when (>= (unbox index) N)
        (twist))
      ;; shifts:
      ;;    >>   -m
      ;;    <<   +m
      (define y (box (vector-ref state (unbox index))))
      ;; y = y ^ (y >> self.u)
      (set-box! y
                (bitwise-xor (unbox y)
                             (arithmetic-shift (unbox y) (- U))))
      ;; y = y ^ ((y << self.s) & self.b)
      (set-box! y
                (bitwise-xor (unbox y)
                             (bitwise-and B
                                          (arithmetic-shift (unbox y)
                                                            S))))
      ;; y = y ^ ((y << self.t) & self.c)
      (set-box! y
                (bitwise-xor (unbox y)
                             (bitwise-and C
                                          (arithmetic-shift (unbox y)
                                                            T))))
      ;; y = y ^ (y >> self.l)
      (set-box! y
                (bitwise-xor (unbox y)
                             (arithmetic-shift (unbox y) (- L))))
      (set-box! index (add1 (unbox index)))
      (int32 (unbox y)))

    ;; twist
    ;; Updates the state of PRNG, as defined in the documentation for
    ;; MT19937
    (define/private (twist)
      (define first-bitmask #x80000000)
      (define last-bitmask #x7FFFFFFF)

      (for ([i (in-range 624)])
        (define idx (modulo (add1 i) 624))
        (define first-i (bitwise-and first-bitmask
                                     (vector-ref state i)))
        (define last-i (bitwise-and last-bitmask
                                    (vector-ref state idx)))
        (define temp (box (int32 (bitwise-ior first-i last-i))))
        (if (zero? (modulo (unbox temp) 2))
            (set-box! temp
                      (arithmetic-shift (unbox temp) -1))
            (set-box! temp
                      (bitwise-xor
                       A
                       (arithmetic-shift (unbox temp) -1))))
        (vector-set! state i
                     (bitwise-xor
                      (unbox temp)
                      (vector-ref state
                                  (modulo (+ i M)
                                          624)))))
      (set-box! index 0))))

(module+ test
  (define mt (new MT19937% [seed 1131464071]))

  (for ([line (file->lines "../../testdata/21.txt")])
    (let ([gen-num (send mt generate-number)])
      (when (not (equal? gen-num (string->number line)))
        (begin
          (printf "Failed. Expected ~v, got ~v\n" (string->number line) gen-num)
          (exit))))))
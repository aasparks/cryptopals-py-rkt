#lang racket

(require "../set1/c1.rkt"
         "md4-math.rkt"
         "md4-rounds.rkt")
; MD4
;; My implementation of MD4, using the original
;; documentation from here
;; http://practicalcryptography.com/hashes/md4-hash/
(provide md4)

(define DEBUG #false)
;; It turns out to be almost identical to SHA-1
;; until digestion.

; a State is a
;  - hash - vector hash value
;  - length - message length
;  - msg - the message itself
(define-struct State (hash length msg) #:transparent)

; default state
(define init-hash (vector #x67452301 #xefcdab89 #x98badcfe #x10325476))

; md4 : bytes? (vector integer?) integer? -> State?
; top-level define for the MD4 hash
(define (md4 msg [inject-state init-hash] [inject-len 0])
  (digest
   (preprocess (init-state msg inject-state inject-len))))

; init-state : bytes? (vector integer?) integer? -> State?
; creates the initial State structure for the MD4 hash
(define (init-state msg start-hash start-len)
  (State start-hash
         (if (zero? start-len)
             (bytes-length msg)
             start-len)
         msg))

; preprocess : State? -> State?
; handles the padding of the message exactly like SHA-1
(define (preprocess state)
  (define msg-len (bytes-length (State-msg state))) ; don't use passed in len b/c of c30
  (define msg-bit-len (* 8 (State-length state)))
  ; pad the message
  (define new-len
    (*
     64 ; block size
     (ceiling (/ (+ msg-len 9) 64)))) ; num blocks
  (define new-msg (make-bytes new-len 0)) ; create buffer
  ; fill buffer with msg + the 1 bit
  (bytes-copy! new-msg 0 (bytes-append
                          (State-msg state)
                          (make-bytes 1 #x80)))
  ; append the length to the end
  (define msg-tail (integer->integer-bytes msg-bit-len 8 #f #f))
  (bytes-copy! new-msg
               (- new-len (bytes-length msg-tail))
               msg-tail)
  ; DEBUG STATEMENT
  (when DEBUG
    (printf "State after preprocessing:\n")
    (printf "MSG: ~v\nLEN: ~v\n" (ascii->hex new-msg)
            new-len))
  
  ; return the new state
  (State (State-hash state)
         new-len
         new-msg))

; digest : State -> bytes?
; digests each block 
(define (digest state)
  #| Process each 16-word block, adding the result
     of the digestion to the previous four registers |#
  (apply bytes-append
         (map
          (λ (num)
            (integer->integer-bytes num 4 #f #f))
          (vector->list
           (foldl digest-block
                  (State-hash state)
                  (split-msg (State-msg state) 64))))))

; digest-block : (vector bytes?) bytes? -> (vector bytes?)
; digests a single block and returns the result
(define (digest-block block old-regs)
  (when DEBUG
    (printf "Block ~v\n" (ascii->hex block))
    (printf "oldregs ~v\n" old-regs))
  (define-values (A B C D)
    (apply values (vector->list old-regs)))
  (define-values (AA BB CC DD)
    (apply values (list A B C D)))
  (define X (block->x block))
  (sum-vectors old-regs
               (round3
                (round2
                 (round1 old-regs X)
                 X)
                X)))

; block->x : bytes? -> (vector integer?)
; converts a block into a vector of 16 words
(define (block->x block)
  (list->vector
   (map
    (λ (num)
      (integer-bytes->integer num #f #f))
    (split-msg block 4))))

; split-msg :  bytes? -> (list bytes?)
; splits the message into 16-word blocks
(define (split-msg msg n)
  (cond
    [(= 0 (bytes-length msg)) empty]
    [else (cons (subbytes msg 0 n)
                (split-msg (subbytes msg n) n))]))
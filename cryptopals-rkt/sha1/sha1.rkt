#lang racket

(require "../set1/c1.rkt"
         "sha1-math.rkt")
(provide sha-1)

(define DEBUG #false)

; SHA-1 implementation

;; Okay so, Racket does provide SHA1 through
;;   (require file/sha1)
;; but they want me to implement it myself
;; and I want to as well.
;;
;; So how do I want to do this?
;; SHA1 is quite imperative, so it may end
;; up being that way. I'm going to follow
;; the FIPS 180-4 spec for this, not pseudocode
;; or another implementation.
;;
;; The first thing to think about here is
;; how to avoid using objects.
;; I think this can be avoided by using structs, because,
;; unlike the Mersenne Twister, it is only called once.
;; So let's save the state in a struct.

; a State is a
;  - hash - vector hash value
;  - length - message length
;  - msg - the message itself
(define-struct State (hash length msg) #:transparent)

; top-level sha-1 function
; sha1 : bytes? (vector integer?) integer? -> bytes?
; initializes and runs the SHA-1 algorithm on the given message
(define (sha-1 msg (init-point init-hash) (init-length 0))
  (digest
   (preprocess
    (init-state msg init-point init-length))))

;; We know the default state
(define init-hash (vector #x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0))

; init-state : bytes? (vector integer?) integer? -> State?
; creates the initial state of the SHA1 with a message
(define (init-state msg start-state start-len)
  (State start-state
         (if (= start-len 0)
             (bytes-length msg)
             start-len)
         msg))

#| Preprocessing

Preprocessing shall take place before hash computation begins.
This consists of three steps: padding the message, parsing the
padded message into message blocks, and setting the initial
hash value.

|#

; preprocess : State -> State
;; does as stated above
(define (preprocess state)
  (define msg-len (bytes-length (State-msg state))) ; don't use passed in len b/c of c29
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
  (define msg-tail (integer->integer-bytes msg-bit-len 8 #f #t))
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

#|
   SHA-1 may be used to hash a message, M, having a length of L bits.
   The algorithm uses
     1. a message schedule of 80 32-bit words
     2. five working variables of 32 bits each
     3. a hash value of 5 32-bit words
   The final result of SHA-1 is a 160-bit message digest.
|#

; digest : state? -> bytes?
; digests each individual block and concatenates to a final result
(define (digest state)
  (define h (box (State-hash state)))
  (for ([i (in-range (/ (State-length state) 64))])
    ; 1. prepare the message schedule
    (define w (prepare-message-sched (State-msg state) i))
    ; digest the block, given w and h
    (set-box! h (digest-block w (unbox h))))
  (apply
   bytes-append
   (map
    (λ (num)
      (integer->integer-bytes
       num 4 #f #t))
    (vector->list (unbox h)))))

; digest-block : (vector? bytes?) bytes? -> (vector? bytes?)
; digests an individual block, given the message schedule
; and the previous hash values
(define (digest-block w hash)
  ; 2. Initialize the five working variables
  (define-values (a b c d e)
    (apply values
           (vector->list hash)))
  (define temp 0)
  ; 3. For t=0 to 79, run F,
  (for ([i (in-range 80)])
    (define-values (f k)
      (cond
        [(< i 20) (values ch #x5A827999)]
        [(< i 40) (values parity #x6ED9EBA1)]
        [(< i 60) (values maj #x8F1BBCDC)]
        [else (values parity #xCA62C1D6)]))
    ; i know this style is far from ideal in Racket
    ; but I'm not sure how else to do this. The algorithm
    ; calls for mutation...
    (set! temp
          (bitwise-and
           (+
            (rotl a 5)
            (f b c d)
            e
            k
            (vector-ref w i))
           #xFFFFFFFF))
    (set! e d)
    (set! d c)
    (set! c (rotl b 30))
    (set! b a)
    (set! a temp)
    (when DEBUG
      (printf "END OF ROUND ~v: ~X ~X ~X ~X ~X ~X\n"
              i a b c d e k)))
  (vector-map (λ (a b)
                (bitwise-and
                 (+ a b)
                 #xFFFFFFFF))
              hash
              (vector a b c d e)))

(module+ test
  (require rackunit)

  ;;;;; PREPROCESS TESTS

  ; 1 block message
  (define actual-state (preprocess
                        (init-state
                         #"abc"
                         init-hash
                         0)))
  (check-equal? (State-hash actual-state)
                init-hash)
  (check-equal? (State-length actual-state)
                64)
  (check-equal? (State-msg actual-state)
                (apply bytes-append
                       (map hex->ascii
                            (list
                             #"61626380"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000000"
                             #"00000018"))))

  ; 2 block message
  (set! actual-state
        (preprocess
         (init-state
          #"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
          init-hash
          0)))
  (check-equal? (State-length actual-state)
                128)
  (check-equal? (State-msg actual-state)
                (apply
                 bytes-append
                 (map hex->ascii
                      (list
                       #"61626364"
                       #"62636465"
                       #"63646566"
                       #"64656667"
                       #"65666768"
                       #"66676869"
                       #"6768696A"
                       #"68696A6B"
                       #"696A6B6C"
                       #"6A6B6C6D"
                       #"6B6C6D6E"
                       #"6C6D6E6F"
                       #"6D6E6F70"
                       #"6E6F7071"
                       #"80000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"00000000"
                       #"000001C0")))))
#lang racket

(require "../set1/c1.rkt")
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
; sha1 : bytes? -> bytes?
; initializes and runs the SHA-1 algorithm on the given message
(define (sha-1 msg)
  (digest
   (preprocess
    (init-state msg))))

;; We know the default state
(define init-hash (vector #x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0))

; init-state : bytes? -> State?
; creates the initial state of the SHA1 with a message
(define (init-state msg)
  (State init-hash (bytes-length msg) msg))

#| Preprocessing

Preprocessing shall take place before hash computation begins.
This consists of three steps: padding the message, parsing the
padded message into message blocks, and setting the initial
hash value.

|#

; preprocess : State -> State
;; does as stated above
(define (preprocess state)
  (define msg-len (State-length state))
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

; split-msg : bytes? -> (listof bytes?)
; splits the message into a list of 4-byte
; blocks
(define (split-msg msg)
  (cond
    [(= 0 (bytes-length msg)) empty]
    [else (cons (subbytes msg 0 4)
                (split-msg (subbytes msg 4)))]))


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
  #|
   SHA-1 uses a sequence of logical functions. Each function operates
   on three 32-bit words (x, y, and z), and produces a 32-bit word
   as output. The functions are defined as follows
     Ch(x, y, z) = (x & y) ^ (!x & z)            0  <= t <= 19
     Parity(x, y, z) = x ^ y ^ z                 20 <= t <= 39
     Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)  40 <= t <= 59
     Parity                                      60 <= t <= 79
  |#
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
              i a b c d e k))
    )
  (vector-map (λ (a b)
                (bitwise-and
                 (+ a b)
                 #xFFFFFFFF))
              hash
              (vector a b c d e)))

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

;; The functions that define f during digest
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

;; Tests
(module+ test
  (require rackunit)
  ;;; Okay so I found some awesome test vectors that include
  ;;; using really large inputs. I'd like to use this opportunity to
  ;;; time these tests in both languages and see what kind of result I
  ;;; get. Obviously, I'm not a master of optimizing Racket so there
  ;;; are probably plenty of places in my code where I'm doing things
  ;;; the slow way. Let's just see what happens.

  ; time-test : string? (any/c -> any/c) => void
  ; counts the time it takes to perform the check for each
  ; given test. This includes the time required to build the
  ; byte-strings before running (hopefully negligible), and the
  ; time for check-equal? to do what it does internally (also hopefully
  ; negligible).
  (define (time-test name f)
    (define t (current-inexact-milliseconds))
    (f)
    (printf "Test ~v completed in ~v ms\n"
            name
            (- (current-inexact-milliseconds) t)))

  ; simple split-msg test
  (check-equal? (list 4 4)
                (map bytes-length
                     (split-msg
                      (make-bytes 8 65))))

  ;;;;;
  ;;;;; PREPROCESS TESTS
  ;;;;;

  ; 1 block message
  (define actual-state (preprocess (init-state #"abc")))
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
         (init-state #"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
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
                       #"000001C0"))))

  ;;;;
  ;;;; SHA-1 TEST VECTORS
  ;;;;  NOTE: These are timed tests
  ; "abc"
  (time-test
   "abc"
   (λ ()
     (check-equal?
      (ascii->hex (sha-1 #"abc"))
      (bytes-append
       #"a9993e36"
       #"4706816a"
       #"ba3e2571"
       #"7850c26c"
       #"9cd0d89d"))))

  ; ""
  (time-test
   "empty string"
   (λ ()
     (check-equal?
      (ascii->hex (sha-1 #""))
      (bytes-append
       #"da39a3ee"
       #"5e6b4b0d"
       #"3255bfef"
       #"95601890"
       #"afd80709"))))

  ; 2 blocks
  (time-test
   "2 blocks"
   (λ ()
     (check-equal?
      (ascii->hex
       (sha-1 #"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
      (bytes-append
       #"84983e44"
       #"1c3bd26e"
       #"baae4aa1"
       #"f95129e5"
       #"e54670f1"))))

  ; 4 blocks
  (time-test
   "4 blocks"
   (λ ()
     (check-equal?
      (ascii->hex
       (sha-1 #"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
      (bytes-append
       #"a49b2446"
       #"a02c645b"
       #"f419f995"
       #"b6709125"
       #"3a04a259"))))

  ; 1 million a's
  (time-test
   "1 million a's"
   (λ ()
     (check-equal?
      (ascii->hex
       (sha-1 (make-bytes 1000000 #x61)))
      (bytes-append
       #"34aa973c"
       #"d4c4daa4"
       #"f61eeb2b"
       #"dbad2731"
       #"6534016f")))))
#lang racket

#|
   This file contains the tests for SHA-1
|#

(module+ test
  (require rackunit
           "sha1.rkt"
           "../set1/c1.rkt")
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
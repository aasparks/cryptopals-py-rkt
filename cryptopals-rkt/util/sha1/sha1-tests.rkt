#lang racket

#|
   This file contains the tests for SHA-1
|#

(module+ test
  (require rackunit
           "../sha1.rkt"
           "../test.rkt"
           "../../set1/c1.rkt")
  ;;; Okay so I found some awesome test vectors that include
  ;;; using really large inputs. I'd like to use this opportunity to
  ;;; time these tests in both languages and see what kind of result I
  ;;; get. Obviously, I'm not a master of optimizing Racket so there
  ;;; are probably plenty of places in my code where I'm doing things
  ;;; the slow way. Let's just see what happens.

  (define sha1-tests
    (test-suite
     "SHA-1"
     (test-case "empty string"
                (check-equal?
                 (ascii->hex (sha-1 #""))
                 #"da39a3ee5e6b4b0d3255bfef95601890afd80709"))
     (test-case "abc"
                (check-equal?
                 (ascii->hex (sha-1 #"abc"))
                 #"a9993e364706816aba3e25717850c26c9cd0d89d"))
     (test-case "2 blocks"
                (check-equal?
                 (ascii->hex
                  (sha-1 #"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
                 #"84983e441c3bd26ebaae4aa1f95129e5e54670f1")
                )
     (test-case "4 blocks"
                (check-equal?
                 (ascii->hex
                  (sha-1 #"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
                 #"a49b2446a02c645bf419f995b67091253a04a259"))
     (test-case "1 million a's"
                (check-equal?
                 (ascii->hex
                  (sha-1 (make-bytes 1000000 #x61)))
                 #"34aa973cd4c4daa4f61eeb2bdbad27316534016f"))))
  (time-test sha1-tests))
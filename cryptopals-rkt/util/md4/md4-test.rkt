#lang racket

#| This file contains the tests for MD4 |#

(module+ test
  (require rackunit
           "../../set1/c1.rkt"
           "../test.rkt"
           "../md4.rkt")

  (define md4-tests
    (test-suite
     "MD4"
     (test-case "empty string"
                (check-equal?
                 (ascii->hex (md4 #""))
                 #"31d6cfe0d16ae931b73c59d7e0c089c0"))
     (test-case "abc"
                (check-equal?
                 (ascii->hex (md4 #"abc"))
                 #"a448017aaf21d8525fc10ae87aa6729d"))
     (test-case "2 blocks"
                (check-equal?
                 (ascii->hex
                  (md4 #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
                 #"043f8582f241db351ce627e153e7f0e4"))
     (test-case "1 million A's"
                (check-equal?
                 (ascii->hex
                  (md4 (make-bytes 1000000 65)))
                 #"a13f9ee75c400d8e6837bd724fb92d66"))))


  (time-test md4-tests))
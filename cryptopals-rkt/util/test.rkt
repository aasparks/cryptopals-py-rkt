#lang racket/base

(require rackunit
         rackunit/text-ui)

(provide time-test)

(define (time-test suite)
  (define-values (result cpu real gc) (time-apply run-tests (list suite)))
  (printf "in ~v seconds\n" (exact->inexact (/ cpu 1000))))


(module+ test
  (define suite
    (test-suite "Example"
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)))
    (time-test suite))
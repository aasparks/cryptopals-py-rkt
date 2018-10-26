#lang racket/base

(require rackunit
         rackunit/text-ui)

(provide time-test
         time)

; time-test : test-suite? -> void
;; runs the given rackunit test suite and prints
;; out the execution time in seconds
(define (time-test suite)
  (define-values (result cpu real gc) (time-apply run-tests (list suite)))
  (printf "in ~v seconds\n" (exact->inexact (/ cpu 1000))))

; time-it : (void -> void) -> real?
;; times the execution of the given function
(define (time-it f)
  (define-values (result cpu real gc) (time-apply f '()))
  (exact->inexact (/ cpu 1000)))


(module+ test
  (define suite
    (test-suite "Example"
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)
               (check-equal? 1 1)))
    (time-test suite))
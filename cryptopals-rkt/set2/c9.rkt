#lang racket

(provide pkcs7-pad)

;; Challenge 9
;; Implement PKCS7 padding
(define (pkcs7-pad txt [l 16])
  (let ([n (- l (modulo (bytes-length txt) l))])
    (bytes-append txt (make-bytes n n))))

(module+ test
  (require rackunit)
  (check-equal? (pkcs7-pad #"YELLOW SUBMARINE" 20)
                #"YELLOW SUBMARINE\x04\x04\x04\x04"))
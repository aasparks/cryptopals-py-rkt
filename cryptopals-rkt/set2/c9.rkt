#lang racket

(provide pkcs7-pad
         pkcs7-unpad)

;; Challenge 9
;; Implement PKCS7 padding
(define (pkcs7-pad txt [l 16])
  (let ([n (- l (modulo (bytes-length txt) l))])
    (bytes-append txt (make-bytes n n))))

;; Let's go ahead and do unpad
(define (pkcs7-unpad txt [l 16])
  (let ([n (bytes-ref txt (sub1 (bytes-length txt)))])
    ;; i could just subbytes here but I want to error
    ;; check, making sure that the padding is VALID
    (sub-last-byte txt n n)))
(define (sub-last-byte txt pad n)
  (if (zero? n)
      txt
      (if (equal? (bytes-ref txt (sub1 (bytes-length txt))) pad)
          (sub-last-byte (subbytes txt 0 (sub1 (bytes-length txt))) pad (sub1 n))
          (error "padding error"))))

(module+ test
  (require rackunit)
  (check-equal? (pkcs7-pad #"YELLOW SUBMARINE" 20)
                #"YELLOW SUBMARINE\x04\x04\x04\x04")
  (check-equal? (pkcs7-unpad #"YELLOW SUBMARINE\x04\x04\x04\x04")
                #"YELLOW SUBMARINE"))
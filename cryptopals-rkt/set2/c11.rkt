#lang racket

; Challenge 11
;; An ECB/CBC Detection Oracle
(require racket/random
         "c9.rkt"
         "c10.rkt"
         "../aes/aes.rkt"
         "../set1/c1.rkt"
         "../set1/c8.rkt")

; Encrypts using an unknown mode with random
; data inserted
(define (encryption-oracle txt)
  (let ([key (crypto-random-bytes 16)]
        [ecb (equal? 1 (random 0 2))]
        [before (crypto-random-bytes (random 5 11))]
        [after (crypto-random-bytes (random 5 11))])
    (if ecb
        (aes-128-ecb-encrypt (pkcs7-pad (bytes-append before txt after))
                             key)
        (aes-128-cbc-encrypt (pkcs7-pad (bytes-append before txt after))
                             key
                             (crypto-random-bytes 16)))))

; Determines if the oracle used ECB or CBC
(define (ecb-or-cbc txt)
  (is-ecb? (encryption-oracle txt)))


(module+ test
  (require rackunit)


  ; Same as the python solution, we will run this
  ; a bunch of times and see if CBC and ECB are
  ; roughly equal in frequency.

  ;; again, we use the solution to challenge 10
  (define test-key #"YELLOW SUBMARINE")
  (define test-iv (make-bytes 16 0))
  (define pt (aes-128-cbc-decrypt (base64->ascii (file->bytes "../../testdata/10.txt"))
                                  test-key
                                  test-iv))
  (define tcount
    (for/sum ([i (in-range 50)])
      (if (ecb-or-cbc pt) 1 0)))
  (define fcount (- 50 tcount))
  (printf "ECB: ~v\n" tcount)
  (printf "CBC: ~v\n" fcount))
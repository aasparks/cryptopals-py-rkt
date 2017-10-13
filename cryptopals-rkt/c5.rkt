#lang racket

(require "c1.rkt"
         "c2.rkt"
         "c3.rkt"
         "c4.rkt")
(provide repeat-key
         repeating-key-xor)

; Challenge 5
;; Implement repeating-key XOR

;; extend the key repeating to size n
(define (repeat-key key n)
  (list->bytes
   (build-list n
               (λ (i)
                 (list-ref (bytes->list key)
                           (modulo i (bytes-length key)))))))

;; repeating key XOR
(define (repeating-key-xor txt key)
  (xorstrs txt (repeat-key key (bytes-length txt))))

;; solution to challenge 5
(define (challenge5)
  (define pt (bytes-append
              #"Burning 'em, if you ain't quick and nimble\n"
              #"I go crazy when I hear a cymbal"))
  (repeating-key-xor pt #"ICE"))

(module+ test
  (require rackunit)
  (check-equal? (repeat-key #"ICE" 6)
                #"ICEICE")
  (check-equal? (repeat-key #"ICE" 5)
                #"ICEIC")
  (check-equal? (repeat-key #"ICE" 15)
                #"ICEICEICEICEICE")
  (define ans (bytes-append
              #"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
              #"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
  (check-equal? (ascii->hex (challenge5))
                ans)
  )
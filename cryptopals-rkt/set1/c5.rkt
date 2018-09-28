#lang racket

(require "c1.rkt"
         "c2.rkt"
         "c3.rkt"
         "c4.rkt")
(provide repeat-key
         repeating-key-xor)
#|
   Here is the opening stanza of an important work of the
   English language:
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal

   Encrypt it, under the key "ICE", using repeating-key XOR.

   In repeating-key XOR, you'll sequentially apply each byte of the key;
   the first byte of plaintext will be XOR'd against I, the next C, the next E,
   then I again for the 4th byte, and so on.

   It should come out to:
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

   Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt
   your mail. Encrypt your password file. Your .sig file. Get a feel for it.
   I promise, we aren't wasting your time with this.
|#

; Challenge 5
;; Implement repeating-key XOR

; repeat-key : bytes integer -> bytes
;; extend the key, repeating to size n
(define (repeat-key key n)
  (define diff (ceiling (/ n (bytes-length key))))
  (subbytes
   (apply bytes-append
          (build-list diff (λ (_) key)))
   0
   n))

; repeating-key-xor : bytes bytes -> bytes
;; repeating key XOR
(define (repeating-key-xor txt key)
  (xorstrs txt (repeat-key key (bytes-length txt))))

(module+ test
  (require rackunit)
  (check-equal? (repeat-key #"ICE" 6)
                #"ICEICE")
  (check-equal? (repeat-key #"ICE" 5)
                #"ICEIC")
  (check-equal? (repeat-key #"ICE" 15)
                #"ICEICEICEICEICE")

  ; Challenge 5 solution
  (define pt (bytes-append
              #"Burning 'em, if you ain't quick and nimble\n"
              #"I go crazy when I hear a cymbal"))
  (define actual
    (ascii->hex (repeating-key-xor pt #"ICE")))
  (define expected
    (bytes-append
     #"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
     #"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))
  (check-equal? actual
                expected))
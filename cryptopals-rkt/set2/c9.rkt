#lang racket

;; Challenge 9
;; Implement PKCS7 padding

(provide pkcs7-pad
         pkcs7-unpad)

#|
   A block cipher transforms a fixed-sized block of plaintext into
   ciphertext. But we almost never want to transform a single block;
   we encrypt irregularly sized messages.

   One way we account for irregularly-sized messages is by padding,
   creating a plaintext that is an even multiple of the blocksize.
   The most popular padding scheme is called PKCS#7.

   So: pad any block to a specific block length, by appending the number
   of bytes of padding to the end of the block. For instance,
     "YELLOW SUBMARINE"
   ...padded to 20 bytes would be
     "YELLOW SUBMARINE\x04\x04\x04\x04"

|#

; pkcs7-pad : bytes [integer] -> bytes
;; pads according to the pkcs7 standard
(define (pkcs7-pad txt [l 16])
  (let ([n (- l (modulo (bytes-length txt) l))])
    (bytes-append txt (make-bytes n n))))

; pkcs7-unpad : bytes [integer] -> bytes
;; unpads to the pkcs7 standard, with validation checks
(define (pkcs7-unpad txt [l 16])
  (define n (bytes-ref txt (sub1 (bytes-length txt))))
  (if (or (> n l) (zero? n))
      (error "padding error")
      (sub-last-byte txt n n)))

(define (sub-last-byte txt pad n)
  (define len (bytes-length txt))
  (cond
    [(zero? n) txt]
    [(equal? pad (bytes-ref txt (sub1 len)))
     (sub-last-byte (subbytes txt 0 (sub1 len)) pad (sub1 n))]
    [else (error "padding error")]))

(module+ test
  (require rackunit)
  (check-equal? (pkcs7-pad #"YELLOW SUBMARINE" 20)
                #"YELLOW SUBMARINE\x04\x04\x04\x04")
  (check-equal? (pkcs7-unpad #"YELLOW SUBMARINE\x04\x04\x04\x04")
                #"YELLOW SUBMARINE")
  (check-exn exn:fail?
             (λ ()
               (pkcs7-unpad #"YELLOW SUBMARINE\x04\x03\x04\x04"))))
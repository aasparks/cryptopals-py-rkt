#lang racket/base

;; Challenge 8
;; Detect AES in ECB mode

(require "../util/conversions.rkt"
         racket/list
         racket/file)
(provide is-ecb?)

#|
   In this file are a bunch of hex-encoded ciphertexts.

   One of them has been encrypted with ECB.

   Detect it.

   Remember that the problem with ECB is that it is
   stateless and deterministic; the same 16-byte
   plaintext block will always produce the same
   16-byte ciphertext.
|#

; is-ecb? : bytes [integer] -> boolean
;; determines if the txt is encrypted with ECB
;; by looking for any repeated blocks
(define (is-ecb? txt)
  (>= (count-repeated-blocks txt) 1))

; count-repeated-blocks : bytes [integer] -> integer
;; Returns the number of repeated blocks
;; in the given text.
(define (count-repeated-blocks txt [block-size 16])
  ;; Let's break the txt up into a list
  ;; of 16-byte byte strings and count
  ;; how many repeated elements the list has
  (define lst (bytes->list/blocks txt block-size))
  (define lst-no-dups (remove-duplicates lst))
  (- (length lst) (length lst-no-dups)))

; bytes->list/blocks : bytes integer -> (listof bytes)
;; Break a byte string into a list
;; of n-length byte strings
(define (bytes->list/blocks txt n)
  (if (<= (bytes-length txt) n)
      (cons txt empty)
      (cons (subbytes txt 0 n)
            (bytes->list/blocks
             (subbytes txt n) n))))

; find-ecb-line : string -> bytes
;; finds the line in the given file that is ECB encoded
(define (find-ecb-line file)
  (define file-lines (file->bytes-lines file #:mode 'text))
  (filter (λ (bstr)
            (is-ecb? (hex->ascii bstr)))
          file-lines))

(module+ test
  (require rackunit
           "../util/test.rkt")
  
  (define test-string #"abcdef01abcd")
  (check-equal? (bytes->list/blocks test-string 4)
                (list #"abcd" #"ef01" #"abcd"))
  (check-equal? (count-repeated-blocks test-string 4)
                1)
  
  ; Challenge 8 Solution
  (define expected
    (bytes-append
     #"d880619740a8a19b7840a8a31c810a3d08649af70dc"
     #"06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0"
     #"348542bb5708649af70dc06f4fd5d2d69c744cd2839"
     #"475c9dfdbc1d46597949d9c7e82bf5a08649af70dc0"
     #"6f4fd5d2d69c744cd28397a93eab8d6aecd56648915"
     #"4789a6b0308649af70dc06f4fd5d2d69c744cd283d4"
     #"03180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c"
     #"123c58386b06fba186a"))

  (define challenge8-test
    (test-suite
     "Challenge 8"
     (check-equal? (find-ecb-line "../../testdata/8.txt")
                   (list expected))))

  (time-test challenge8-test))
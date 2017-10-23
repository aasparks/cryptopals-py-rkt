#lang racket

(require
  "c1.rkt"
  "c7.rkt")

;; Challenge 8
;; Detect AES in ECB mode

;; Following the python solution, take the line
;; with the most repeated blocks
(define (is-ecb? txt [max-size 2])
  (> (count-repeated-blocks txt) max-size))

;; Returns the number of repeated blocks
;; in the given text
;; How to do this...?
;; Let's break the txt up into a list
;; of 16-byte byte strings and count
;; how many repeated elements the list has
(define (count-repeated-blocks txt [block-size 16])
  (let* ([lst (bytes->list/blocks txt block-size)]
         [lst-no-dups (remove-duplicates lst)])
    (- (length lst) (length lst-no-dups))
    ))

;; Break a byte string into a list
;; of n-length byte strings
(define (bytes->list/blocks txt n)
  (if (<= (bytes-length txt) n)
      (cons txt empty)
      (cons (subbytes txt 0 n)
            (bytes->list/blocks
             (subbytes txt n (bytes-length txt))
             n))))


;; Solution to Challenge 8
;; Breaks the file into lines, and finds the lines
;; that are ecb encoded. Should only find one.
(define (challenge8)
  (filter
   second
   (map
    (λ (bstr) (list bstr
                    (is-ecb? (hex->ascii bstr) 2)))
    (file->bytes-lines "8.txt" #:mode 'text))))

(module+ test
  (require rackunit)
  (define test-string #"abcdef01abcd")
  (check-equal? (bytes->list/blocks test-string 4)
                (list #"abcd" #"ef01" #"abcd"))
  (check-equal? (count-repeated-blocks test-string 4)
                1)
  (check-equal? (challenge8)
                (list (list #"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
                            #t))))
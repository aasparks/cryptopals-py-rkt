#lang racket

(require
  "c1.rkt"
  "c2.rkt"
  "c3.rkt"
  "c5.rkt")
(provide (all-defined-out))

; Challenge 6
;; Break repeating key xor

;; The instructions for this given nicely.

#|
   1. Let KEYSIZE be the guessed length of the key.
   try values from 2 to (say) 40.
|#
(define maxKeysize 40)

#|
   2. Write a function to compute the edit distance
   (Hamming distance) between two strings. Hamming
   distance is the number of differing bits.
|#
; hamming-distance : bytes bytes -> integer
;; computes the hamming distance of two byte strings
(define (hamming-distance str1 str2)
  (apply
   +
   (map
    (λ (num) (count-chars #\1 (number->string num 2)))
        (bytes->list (xorstrs str1 str2)))))

#|
   3. For each KEYSIZE, take the first KEYSIZE worth of bytes
   and the second KEYSIZE worth of bytes, and find the edit
   distance between them. Normalize this result by dividing
   by KEYSIZE
|#
; edit-distance : real bytes -> real
;; gets the normalized edit distance for the byte string
(define (edit-distance keysize txt)
  (/ (for/sum ([i (in-range 1 maxKeysize)])
       (hamming-distance (get-block txt i keysize)
                         (get-block txt (add1 i) keysize)))
     keysize))

; get-block : bytes integer integer -> bytes
;; get the n'th block of txt of size size
(define (get-block txt n size)
  (subbytes txt
            (min (* n size) (bytes-length txt))
            (min (* (add1 n) size) (bytes-length txt))))

#|
   4. The KEYSIZE with the smallest normalized edit distance
   is probably the key. You could proceed perhaps with the smallest 2-3
   KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2.
|#
; get-keysize : bytes -> integer
;; guesses the keysize by taking the size with the smallest edit distance
(define (get-keysize txt)
  (car
   (first
   (sort
   ;; get the edit distance for each keysize
   (for/list ([i (in-range 1 maxKeysize)])
     (cons i
           (edit-distance i txt)))
   ;; sort by smallest edit distance
   (λ (x y) (< (cdr x) (cdr y)))))))

#|
   5. Now that you probably know the KEYSIZE:
   break the ciphertext into blocks of KEYSIZE
   length.
|#
; split-ct : integer bytes -> (listof bytes)
;; splits the ciphertext into keysize blocks
(define (split-ct keysize txt)
  (for/list ([i (in-range 0 (/ (bytes-length txt) keysize))])
    (get-block txt i keysize)))

#|
   6. Now transpose the blocks: make a block that is the first
   byte of every block, and a block that is the second byte of every
   block, and so on
|#
; transpose-blocks : (listof bytes) integer -> (listof bytes)
;; transposes the blocks as described above for step 6
(define (transpose-blocks blocks keysize)
  (for/list ([i (in-range keysize)])
    (apply bytes-append
           (map (λ (b)
                  (get-block b i 1))
                blocks))))

#|
   7. Solve each block as if it was single-character XOR.
|#
; solve-blocks : (listof bytes) -> bytes
;; solves each individual block as a single character XOR
(define (solve-blocks blocks)
  (apply bytes
         (map (λ (b) (second (single-byte-xor b)))
              blocks)))

; break-repeating-key : string -> bytes
;; breaks the repeating key XOR for the given file,
;; giving back the key
(define (break-repeating-key file)
  (define ctxt (base64->ascii (file->bytes file)))
  (define ksize (get-keysize ctxt))
  (solve-blocks
   (transpose-blocks
    (split-ct ksize ctxt)
    ksize)))

(module+ test
  (require rackunit)

  (check-equal? (hamming-distance #"this is a test"
                                  #"wokka wokka!!!")
                37)
  (check-equal? (split-ct 3 #"this is a test")
                (list #"thi" #"s i" #"s a" #" te" #"st"))
  (check-equal? (transpose-blocks (split-ct 3 #"this is a test") 3)
                (list #"tss s" #"h  tt" #"iiae"))

  ; Challenge 6 solution
  (define ctxt (base64->ascii (file->bytes "../../testdata/6.txt")))
  (define actual (break-repeating-key "../../testdata/6.txt"))
  (check-equal? actual
                #"Terminator X: Bring the noise")
  #;(repeating-key-xor ctxt actual))
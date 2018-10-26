#lang racket/base

; Challenge 6
;; Break Repeating-key XOR

(require "../util/conversions.rkt"
         "c3.rkt"
         racket/list
         racket/file)
(provide hamming-distance
         break-repeating-key)

#|
   There's a file here. It's been base64'd after being
   encrypted with repeating-key XOR.

   Decrypt it.

   Here's how:

      1. Let KEYSIZE be the guessed length of the key.
         try values from 2 to (say) 40.
      2. Write a function to compute the edit distance
         (Hamming distance) between two strings. Hamming
         distance is the number of differing bits.
      3. For each KEYSIZE, take the first KEYSIZE worth of bytes
         and the second KEYSIZE worth of bytes, and find the edit
         distance between them. Normalize this result by dividing
         by KEYSIZE
      4. The KEYSIZE with the smallest normalized edit distance
         is probably the key. You could proceed perhaps with the smallest 2-3
         KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2.
      5. Now that you probably know the KEYSIZE:
         break the ciphertext into blocks of KEYSIZE
         length.
      6. Now transpose the blocks: make a block that is the first
         byte of every block, and a block that is the second byte of every
         block, and so on.
      7. Solve each block as if it was single-character XOR.
      8. For each block, the single-byte XOR key that produces the best looking
         histogram is the repeating-key XOR key byte for that block. Put them
         together and you have the key.

   This code is going to turn out to be surprisingly useful later on. Breaking
   repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
   a "Crypto-101" thing. But more people "know how" to break it than can actually
   break it, and a similar technique breaks something much more important.
|#

(define maxKeysize 40)

; hamming-distance : bytes bytes -> integer
;; computes the hamming distance of two byte strings
(define (hamming-distance str1 str2)
  (apply
   + (map
      (λ (num)
        (count (λ (c) (equal? #\1 c))
               (string->list (number->string num 2))))
      (bytes->list (xorstrs str1 str2)))))

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

; get-keysize : bytes -> integer
;; guesses the keysize by taking the size with the smallest edit distance
(define (get-keysize txt)
  (car
   (argmin cdr
   ;; get the edit distance for each keysize
   (for/list ([i (in-range 1 maxKeysize)])
     (cons i
           (edit-distance i txt))))))

; split-ct : integer bytes -> (listof bytes)
;; splits the ciphertext into keysize blocks
(define (split-ct keysize txt)
  (for/list ([i (in-range 0 (/ (bytes-length txt) keysize))])
    (get-block txt i keysize)))

; transpose-blocks : (listof bytes) integer -> (listof bytes)
;; transposes the blocks as described above for step 6
(define (transpose-blocks blocks keysize)
  (for/list ([i (in-range keysize)])
    (apply bytes-append
           (map (λ (b)
                  (get-block b i 1))
                blocks))))

; solve-blocks : (listof bytes) -> bytes
;; solves each individual block as a single character XOR
(define (solve-blocks blocks)
  (apply bytes
         (map (λ (b) (single-byte-xor b))
              blocks)))

; break-repeating-key : bytes -> bytes
;; breaks the repeating key XOR for the given file,
;; giving back the key
(define (break-repeating-key ctxt)
  (define ksize (get-keysize ctxt))
  (solve-blocks
   (transpose-blocks
    (split-ct ksize ctxt)
    ksize)))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (define ctxt
    (base64->ascii (file->bytes "../../testdata/6.txt")))

  (define helper-tests
    (test-suite
     "Helpers"
     (check-equal? (hamming-distance #"this is a test"
                                     #"wokka wokka!!!")
                   37)
     (check-equal? (split-ct 3 #"this is a test")
                   (list #"thi" #"s i" #"s a" #" te" #"st"))
     (check-equal? (transpose-blocks (split-ct 3 #"this is a test") 3)
                   (list #"tss s" #"h  tt" #"iiae"))
     (check-equal? (get-keysize ctxt)
                   29)))

  (define challenge6-test
    (test-suite
     "Challenge 6"
     (check-equal? (break-repeating-key ctxt)
                #"Terminator X: Bring the noise")))

  (define all-tests
    (test-suite
     "All"
     helper-tests challenge6-test))
  
  (time-test all-tests))
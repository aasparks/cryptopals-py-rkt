#lang racket/base

; Challenge 3
;; Single-byte XOR cipher
(require "../util/conversions.rkt"
         racket/list)
(provide single-byte-xor
         score)

#|
   The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
   ...hash been XOR'd against a single character. Find the key,
   decrypt the message.

   You can do this by hand. But don't: write code to do it for you.
   How? Devise some method for "scoring" a piece of English plaintext.
   Character frequency is a good metric. Evaluate each output and choose
   the one with the best score.
|#

; DEBUG
(define DEBUG #false)

;;; I need to write a function to score a piece of plaintext as
;;; English or not. A simple frequency analysis should work.

;; First let's get a dictionary of the relative character frequency for English.
(define known-freq
  (make-immutable-hash
   (list 
    (cons #\a 0.082) (cons #\b 0.015) (cons #\c 0.028)
    (cons #\d 0.043) (cons #\e 0.127) (cons #\f 0.022)
    (cons #\g 0.020) (cons #\h 0.061) (cons #\i 0.069)
    (cons #\j 0.002) (cons #\k 0.008) (cons #\l 0.040)
    (cons #\m 0.024) (cons #\n 0.067) (cons #\o 0.075)
    (cons #\p 0.019) (cons #\q 0.001) (cons #\r 0.059)
    (cons #\s 0.063) (cons #\t 0.091) (cons #\u 0.028)
    (cons #\v 0.009) (cons #\w 0.024) (cons #\x 0.002)
    (cons #\y 0.019) (cons #\z 0.001))))

; The alphabet in order of greatest frequency to lowest
(define ETAOIN (string->list "etaoinshrdlcumwfgypbvkjxqz"))
; bad char list. when it get's close to the key, the scoring gets
; really close. this list helps eliminate those.
(define BAD-CHARS (bytes->list #"~@#$%^&*=+|<>{}[]()"))

;; Working top-down for this one. First we create a list
;; of all the keys and the score they get. Then we take
;; the one with the largest score. The trick here is getting
;; a good scoring function.

; single-byte-xor : bytes -> byte
;; finds the key by trying every possible value and scoring
;; the plaintext and taking the one with the highest score
(define (single-byte-xor txt)
  (define scores
    (map
     (λ (x) (list
             (score (xorstrs txt (make-bytes (bytes-length txt) x)))
             x))
     (build-list 256 values)))
  (when DEBUG
    (map (λ (score)
           (printf "~v: ~v\n\t~v\n"
                   (second score)
                   (first score)
                   (xorstrs txt
                            (make-bytes (bytes-length txt)
                                        (second score)))))
         scores))
  (second (argmax first scores)))

; score : bytes -> real
;; score a piece of plaintext using frequency analysis
(define (score pt)
  ;; just like the python version, we first throw out
  ;; any strings that are automatically not English
  (if
   (contains-bad-chars? pt)
   0
   ;; count the relative frequency of each character
   ;; and assign a score
   (assign-score
    (get-relative-freqs
     (apply
      string-append
      (regexp-match*
       #rx"[a-z]*"
       (string-downcase
        (bytes->string/utf-8 pt))))))))

; contains-bad-chars? : bytes -> boolean
;; determines if the given bytestring has any byte values
;; that are > 127 or < 32 (except for newline chars)
(define (contains-bad-chars? str)
  (ormap (λ (c) (or (> c 127)
                    (and (< c 32) (not (= c 10)))
                    (member c BAD-CHARS)))
         (bytes->list str)))

; get-relative-freqs : bytes -> hash
;; gets the relative frequencies of a piece of txt as a hash value
(define (get-relative-freqs txt)
  ; make a hash and set all counts to 0
  (define rel-freqs
    (make-hash
     (for/list ([i (in-list ETAOIN)])
       (cons i 0))))
  ; build a count for each char in string
  (for-each (λ (c)
              (hash-set! rel-freqs
                         c (add1 (hash-ref rel-freqs c))))
            (string->list txt))
  ; divide each key by string-length for relative frequency
  (define len (string-length txt)) ; not sure if string-length is O(N)
  (for-each (λ (c)
              (hash-set! rel-freqs
                         c (/ (hash-ref rel-freqs c) len)))
            ETAOIN)
  rel-freqs)

; assign-score : hash -> real
;; assigns a score based on relative frequency of characters
(define (assign-score freq)
  ;; sort of arbitrary choice here.
  ;; if the difference in frequency is < half of
  ;; what the frequency should be, we get a point.
  (apply
   +
   (map
    (λ (c)
      (if (< (abs (- (hash-ref freq c)
                     (hash-ref known-freq c)))
             (/ (hash-ref known-freq c) 2))
          1
          0))
    ETAOIN)))

; Test
(module+ test
  (require rackunit
           "../util/test.rkt")

  (define ct
    (hex->ascii
     #"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

  ; Challenge 3 solution
  (define challenge3
    (test-suite
     "Challenge 3"
     (check-equal? (single-byte-xor ct)
                   88)))

  (time-test challenge3))
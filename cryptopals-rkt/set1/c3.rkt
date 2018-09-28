#lang racket

; Challenge 3
;; Single-byte XOR cipher
(require "c1.rkt"
         "c2.rkt")
(provide single-byte-xor
         count-chars
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

; Frequencies should be within EPSILON of the known frequency
(define EPSILON 0.005)
; The alphabet, in order of greatest frequency to lowest, grouped
; for the scoring function
(define ETAOIN
  (list (string->list "etaoin")
        (string->list "shrdlcumvfg")
        (string->list "ypbvk")
        (string->list "jxqz")))
; The alphabet in order of greatest frequency to lowest
(define A-ETAOIN (string->list "etaoinshrdlcumwfgypbvkjxqz"))
; List of all characters that invalidate the string
(define BAD-CHAR-LIST (append
                       (map integer->char (remove 10 (build-list 32 values)))
                       (string->list "~@#$%^&*(){}+?=/][")))

;; Working top-down for this one. First we create a list
;; of all the keys and the score they get. Then we take
;; the one with the largest score. The trick here is getting
;; a good scoring function.

; single-byte-xor : bytes -> byte
;; finds the key by trying every possible value and scoring
;; the plaintext and taking the one with the highest score
(define (single-byte-xor txt)
  ;; get a list of all possible keys and their
  ;; associated scores as '((score, key, ct), (score, key, ct))
  (define all-keys
    (map
     (λ (x) (score txt x))
     (build-list 256 values)))
  ;; give back the key with the best score
  (first
   (sort
    all-keys
    (λ (x y)
      (> (car x) (car y))))))

; score : bytes byte -> (listof real byte bytes)
;; scores a given ciphertext as english
;; by converting to plaintext and doing
;; frequency analysis
(define (score ct key)
  (list
   (freq-analysis
    (xorstrs
     ct
     (make-bytes (bytes-length ct) key)))
   key
   ct))

; freq-analysis : bytes -> real
;; score a piece of plaintext using frequency analysis
(define (freq-analysis pt)
  ;; just like the python version, we first throw out
  ;; any strings that are automatically not English
  (if
   (contains-bad-chars? pt)
   0
   ;; count the relative frequency of each character
   ;; and assign a score
   (assign-score
    (get-relative-freqs
     (string-downcase
      (bytes->string/utf-8 pt))))))

; contains-bad-chars? : bytes -> boolean
;; determines if a piece of text has non-English characters
(define (contains-bad-chars? txt)
  ;; return true only when a string has no characters
  ;; with ascii value < 32 except for \n
  (with-handlers ([exn:fail?
                   (lambda (exn) #t)])
    (ormap
     (λ (c) (string-contains?
             (bytes->string/utf-8 txt)
             (string c)))
     BAD-CHAR-LIST)))

; get-relative-freqs : bytes -> hash
;; gets the relative frequencies of a piece of txt as a hash value
(define (get-relative-freqs txt)
  (make-hash
   (map (λ (c) (get-freq c txt))
        (string->list "abcdefghijklmnopqrstuvwxyz"))))

; get-freq : char bytes -> (list char real)
;; gets the relative frequency of a character in a string
(define (get-freq c txt)
  (cons c
        (/ (count-chars c txt)
           (string-length txt))))

; count-chars : char string -> integer
;; counts the number of times a character appears
;; in a string
(define (count-chars c str)
  (count (λ (other-char)
           (equal? other-char c))
         (string->list str)))

; assign-score : hash -> real
;; assigns a score based on relative frequency of characters
(define (assign-score freq)
  ;; sort of arbitrary choice here.
  ;; if the difference in frequency is < half of
  ;; what the frequency should be, we get a point.
  (apply
   +
   (map (λ (c)
          (if (< (abs (- (hash-ref freq c)
                         (hash-ref known-freq c)))
                 (/ (hash-ref known-freq c) 2))
              1
              0))
        A-ETAOIN)))

; Test
(module+ test
  (require rackunit)

  ; Challenge 3 solution
  (define ct
    (hex->ascii
     #"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
  (define actual (single-byte-xor ct))
  (check-equal? (second actual) 88)
  (check-equal? (xorstrs
                 ct
                 (make-bytes (bytes-length ct) (second actual)))
                #"Cooking MC's like a pound of bacon"))
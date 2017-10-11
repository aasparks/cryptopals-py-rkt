#lang racket

; Challenge 3
;; Single-byte XOR cipher
(require "c1.rkt"
         "c2.rkt")
(provide (all-defined-out))

;;; I need to write a function to score a piece of plaintext as
;;; English or not. A simple frequency analysis should work.

;; First let's get a dictionary of the relative character frequency for English.
(define known-freq (make-immutable-hash (list 
                                         (cons #\a 0.082)
                                         (cons #\b 0.015)
                                         (cons #\c 0.028)
                                         (cons #\d 0.043)
                                         (cons #\e 0.127)
                                         (cons #\f 0.022)
                                         (cons #\g 0.020)
                                         (cons #\h 0.061)
                                         (cons #\i 0.069)
                                         (cons #\j 0.002)
                                         (cons #\k 0.008)
                                         (cons #\l 0.040)
                                         (cons #\m 0.024)
                                         (cons #\n 0.067)
                                         (cons #\o 0.075)
                                         (cons #\p 0.019)
                                         (cons #\q 0.001)
                                         (cons #\r 0.059)
                                         (cons #\s 0.063)
                                         (cons #\t 0.091)
                                         (cons #\u 0.028)
                                         (cons #\v 0.009)
                                         (cons #\w 0.024)
                                         (cons #\x 0.002)
                                         (cons #\y 0.019)
                                         (cons #\z 0.001))))
(define EPSILON 0.005)
(define ETAOIN (list (string->list "etaoin")
                     (string->list "shrdlcumvfg")
                     (string->list "ypbvk")
                     (string->list "jxqz")))
(define A-ETAOIN (string->list "etaoinshrdlcumwfgypbvkjxqz"))
(define BAD-CHAR-LIST (append
                       (map integer->char (remove 10 (build-list 32 values)))
                       (string->list "~@#$%^&*(){}+?=/][")))

;; Working top-down for this one. First we create a list
;; of all the keys and the score they get. Then we take
;; the one with the largest score. The trick here is getting
;; a good scoring function.


;; Find the key and return it
(define (single-byte-xor txt)
  ;; get a list of all possible keys and their
  ;; associated scores as '((score, key), (score, key))
  (define all-keys
    (map
     (λ (x) (score txt x))
     (build-list 256 values)))
  ;; give back the key with the best score
  (first
   (sort all-keys
         (λ (x y)
           (> (car x) (car y))))))

;; Score a given ciphertext as english
;; by converting to plaintext and doing
;; frequency analysis
(define (score ct key)
  (list (freq-analysis (xorstrs ct
                           (key-extend key (bytes-length ct))))
        key))

;; extend a key to the given length
(define (key-extend key len)
  (make-bytes len key))

;; score a piece of plaintext using frequency analysis
(define (freq-analysis pt)
  ;; just like the python version, we first throw out
  ;; any strings that are automatically not English
  (if
    (contains-bad-chars? pt)
    0
    ;; count the relative frequency of each character
    (assign-score (get-relative-freqs (string-downcase
                                       (bytes->string/utf-8 pt))))))

;; determines if a piece of text has non-English characters
(define (contains-bad-chars? txt)
  ;; return true only when a string has no characters
  ;; with ascii value < 32 except for \n
  (with-handlers ([exn:fail?
                   (lambda (exn) #t)])
    (bytes->string/utf-8 txt)
    (ormap (λ (c) (string-contains? (bytes->string/utf-8 txt) (string c)))
          BAD-CHAR-LIST)))

;; gets the relative frequencies of a piece of txt as a hash value
(define (get-relative-freqs txt)
  (make-hash (map (λ (c) (get-freq c txt))
                    (string->list "abcdefghijklmnopqrstuvwxyz"))))

;; gets the relative frequency of a character in a string
(define (get-freq c txt)
  (cons c
        (/ (count-substring (string c) txt)
           (string-length txt))))

;; thanks Rosetta Code!
(define count-substring
  (compose length regexp-match*))

;; assigns a score based on relative frequency of characters
(define (assign-score freq)
  ;; sort of arbitrary choice here.
  ;; if the difference in frequency is < half
  ;; what the frequency should be, we get a point.
  (apply +
         (map (λ (c)
                (if
                 (< (abs (- (hash-ref freq c)
                            (hash-ref known-freq c)))
                    (/ (hash-ref known-freq c) 2))
                 1 0))
              A-ETAOIN)))



(module+ test
  (require rackunit)
  (define ct (hex->ascii #"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
  ;; I know what the solution should be so let's just assert that it's true
  (define (challenge3)
    (let [(sol (single-byte-xor
                ct))]
      (check-equal? (second sol) 88)
      (check-equal? (xorstrs ct
                           (key-extend (second sol)  (bytes-length ct)))
                    #"Cooking MC's like a pound of bacon")
      (display "pass"))
    )
  (challenge3))















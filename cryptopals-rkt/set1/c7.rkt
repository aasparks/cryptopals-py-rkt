#lang racket/base

; Challenge 7
;; AES in ECB Mode

;; okay so racket has (planet vyzo/crypto)
;; but I thought I would just go ahead and
;; try to implement it myself to see if I could.
;; Turns out I could.
;; This implementation is only designed to
;; complete the challenges here.
;; It is probably much slower and less secure
;; but it was a fun challenge.
(require "../util/aes.rkt"
         "c1.rkt"
         racket/file)

(define DEBUG #true)

#|
    The base64-encoded content in this file has been encrypted via
    AES-128 in ECB mode under the key
      "YELLOW SUBMARINE"
    (case-sensitive, without the quotes; exactly 16 characters).
    Decrypt it. You know the key, after all.
|#

(module+ test
  (require rackunit
           "../util/test.rkt")
  
  (define result
   (aes-128-decrypt
    (base64->ascii (file->bytes "../../testdata/7.txt" #:mode 'text))
    #"YELLOW SUBMARINE"))

  ; I want to time the execution but the result is so long. So I'm going to
  ; decrypt again and check the result. Obviously a bogus test but it
  ; will give me an idea of the execution time of AES
  (define challenge-7
    (test-suite
     "Challenge 7"
     (check-equal? (aes-128-decrypt
                    (base64->ascii (file->bytes "../../testdata/7.txt" #:mode 'text))
                    #"YELLOW SUBMARINE")
                   result)))
  (time-test challenge-7))
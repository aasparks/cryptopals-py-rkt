#lang racket

; Challenge 1
; Convert hex to base64
(require net/base64
         file/sha1)
(require file/sha1)
(provide ascii->base64
         base64->ascii
         ascii->hex
         hex->ascii
         hex->base64
         base64->hex)
;; These functions are provided by net/base64

; ascii -> base64
(define (ascii->base64 bstr)
  (base64-encode bstr ""))

; base64 -> ascii
(define (base64->ascii bstr)
  (base64-decode bstr))



;; The rest are provided by file/sha1

; ascii -> hex
(define (ascii->hex bstr)
  (string->bytes/utf-8 (bytes->hex-string bstr)))

;; hex -> ascii
(define (hex->ascii bstr)
  (hex-string->bytes (bytes->string/utf-8 bstr)))

; hex -> base64
(define (hex->base64 bstr)
  (ascii->base64
   (hex->ascii bstr)))

; base64 -> hex
(define (base64->hex bstr)
  (ascii->hex
   (base64->ascii bstr)))

;; Challenge 1 solution
(define (challenge1)
  (if (equal? (hex->base64 #"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
                #"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
      (display "pass")
      (error "fail")))

;; Test all the functions
(module+ test
  (require rackunit)
  (define asc #"Who lives in a pineapple under the sea?")
  (define hex #"57686f206c6976657320696e20612070696e656170706c6520756e64657220746865207365613f")
  (define b64 #"V2hvIGxpdmVzIGluIGEgcGluZWFwcGxlIHVuZGVyIHRoZSBzZWE/")

  (check-equal? (hex->ascii hex)
                asc)
  (check-equal? (base64->ascii b64)
                asc)
  (check-equal? (ascii->hex asc)
                hex)
  (check-equal? (base64->hex b64)
                hex)
  (check-equal? (hex->base64 hex)
                b64)
  (check-equal? (ascii->base64 asc)
                b64))
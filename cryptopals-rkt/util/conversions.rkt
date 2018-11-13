#lang racket/base

(require "../set1/c1.rkt"
         "../set1/c2.rkt")

(provide ascii->hex
         hex->ascii
         ascii->base64
         base64->ascii
         hex->base64
         base64->hex
         xorstrs
         bytes->integer
         integer->bytes)

; bytes->integer : bytes? boolean? -> integer?
;; converts bytestring of arbitrary length
;; to an integer
(define (bytes->integer bstr [big-endian? #true])
  (define (combine num prev)
    (bitwise-ior (arithmetic-shift prev 8) num))
  (if big-endian?
      (foldl combine 0 (bytes->list bstr))
      (foldr combine 0 (bytes->list bstr))))

; integer->bytes : integer? boolean? -> bytes?
;; converts an integer into a bytestring
(define (integer->bytes num [num-bytes 0] [big-endian? #true])
  (integer->bytes/helper num num-bytes #"" big-endian?))

; integer->bytes/helper : integer? bytes? boolean? -> bytes?
;; recursively converts the number to a bytestring
(define (integer->bytes/helper num num-bytes bstr big-endian?)
  (cond
    [(zero? num)
     (cond
       [(>= (bytes-length bstr) num-bytes) bstr]
       [big-endian? (bytes-append
                     (make-bytes
                      (- num-bytes (bytes-length bstr))
                      0)
                     bstr)]
       [else (bytes-append
              bstr
              (make-bytes
               (- num-bytes (bytes-length bstr)) 0))])]
    [big-endian?
     (integer->bytes/helper
      (arithmetic-shift num -8)
      num-bytes
      (bytes-append (bytes (bitwise-and num #xff))
                    bstr)
      big-endian?)]
    [else (integer->bytes/helper
           (arithmetic-shift num -8)
           num-bytes
           (bytes-append
            bstr (bytes (bitwise-and num #xff)))
           big-endian?)]))

(module+ test
  (require rackunit
           sha)

  (check-equal?
   (bytes->integer #"1234")
   (integer-bytes->integer #"1234" 4 #t))

  (check-equal?
   (bytes->integer #"1234" #f)
   (integer-bytes->integer #"1234" 4 #f))

  (check-equal?
   (integer->bytes (bytes->integer #"1234"))
   #"1234")

  (check-equal?
   (integer->bytes (bytes->integer #"1234" #f) 4 #f)
   #"1234")

  (check-equal?
   (integer->bytes (bytes->integer #"1234") 6)
   #"\0\0001234")

  (check-equal?
   (integer->bytes (bytes->integer #"1234") 6 #f)
   #"4321\0\0")

  ; got these using python's int.from_bytes
  (check-equal? (bytes->integer (sha256 #""))
                102987336249554097029535212322581322789799900648198034993379397001115665086549)

  (check-equal? (bytes->integer (sha256 #"") #f)
                38772261170797515502142737251560910253885555854579348417967781179871348437219))
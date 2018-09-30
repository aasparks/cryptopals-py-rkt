#lang racket

; Challenge 18
;; Implement CTR, The Stream Cipher Mode

;; This is added to my AES implementation
;; Let's just see the result

(module+ test
  (require "../aes/aes.rkt"
           "../set1/c1.rkt"
           rackunit)
  (define expected #"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
  (define actual
    (aes-128-ctr
     (base64->ascii
      (bytes-append #"L77na/nrFsKvynd6HzOoG7GHTLXsT"
                    #"Vu9qvY/2syLXzhPweyyMTJULu/6/k"
                    #"XX0KSvoOLSFQ=="))
     #"YELLOW SUBMARINE"
     0))
  (check-equal? actual expected)
  )
#lang racket

(require racket/random
         "c9.rkt"
         "../aes/aes.rkt")
; Challenge 13
;; ECB cut-and-paste

#|
  Write a k=v parsing routine, as if for a structured
  cookie. The routine should take:
     foo=bar&baz=qux&zap=zazzle
  and produce:
     {
       foo: 'bar',
       baz: 'qux',
       zap: 'zazzle'
     }
|#

(define (parse-cookie cookie)
  (make-hash (map (λ (s) (string-split s "="))
                  (string-split cookie "&"))))

#| Now write a function that encodes a user profile
   in that format, given an email address. You should
   have something like:
     profile_for("foo@bar.com")
   ... and it should produce
     {
        email: 'foo@bar.com',
        uid: 10,
        role: 'user'
     }

   You function should NOT alow encoding '&' or '='. 
|#
; we'll use a global counter for UID
(define UID 0)

(define (profile-for email)
  (set! UID (add1 UID))
  (string-append "email=" (string-replace email #rx"[&=]+" "")
                 "&uid=" UID
                 "&role=user"))


#|
  Now two more easy function. Generate a random AES key, then:
   1. Encrypt the encoded user profile under the key
   2. Decrypt the encoded user profile and parse it
|#
(define KEY (crypto-random-bytes 16))

(define (encrypt-profile email)
  (aes-128-ecb-encrypt (pkcs7-pad (profile-for email))))

(module+ test
  (require rackunit)

  #;(check-equal? (parse-cookie "foo=bar&baz=qux&zap=zazzle")
                (make-hash (list (cons "zap" "zazzle")
                                 (cons "foo" "bar")
                                 (cons "baz" "qux")))
                )
  (check-equal? (profile-for "foo@bar.com")
                "email=foo@bar.com&uid=1&role=user")
  (check-equal? (profile-for "foo&user=admin@bar.com")
                "email=foouseradmin@bar.com&uid=1&role=user"
                )
  
  )
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
  (make-weak-hash (map (λ (s) (string-split s "="))
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
                 "&uid=" (number->string UID)
                 "&role=user"))


#|
  Now two more easy function. Generate a random AES key, then:
   1. Encrypt the encoded user profile under the key
   2. Decrypt the encoded user profile and parse it
|#
(define KEY (crypto-random-bytes 16))

; encrypt a profile for a user given the email
(define (encrypt-profile email)
  (aes-128-ecb-encrypt (pkcs7-pad (string->bytes/utf-8 (profile-for email))) KEY))

; decrypt a user profile
(define (decrypt-profile prof)
  (parse-cookie (bytes->string/utf-8 (pkcs7-unpad (aes-128-ecb-decrypt prof KEY)))))

; creates a fake admin profile
(define (create-admin-profile)
    ; This attack involves block alignment.
    ; 
    ; 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    ; email=sponge@bob .com&uid=2&role= user
    ; email=blahblahbl adminBBBBBBBBBBB &uid=3&role=user
    ; Cut and paste the blocks you want
    ;      email=spongebobsquar&uid=2&role=admin0000000000B
  (let ([first-entry (encrypt-profile "sponge@bob.com")]
         [second-entry (encrypt-profile (bytes->string/utf-8 (bytes-append #"blahblahbladmin" (make-bytes 11 11))))])
    (decrypt-profile (bytes-append (subbytes first-entry 0 32)
                                   (subbytes second-entry 16 32)))))

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
                "email=foouseradmin@bar.com&uid=2&role=user"
                )
  (hash-ref (create-admin-profile) "role")
                      
  
  )
#lang racket/base

; Challenge 13
;; ECB cut-and-paste
(require racket/random
         racket/string
         "../util/aes.rkt"
         "../util/pkcs7.rkt")
(provide encrypt-profile
         decrypt-profile
         create-admin-profile)
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

   Now write a function that encodes a user profile
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

   Now two more easy function. Generate a random AES key, then:
     1. Encrypt the encoded user profile under the key
     2. Decrypt the encoded user profile and parse it

   Using only the user input to (profile_for)
   (as an oracle to generate "valid" ciphertexts)
   and the ciphertexts themselves, make a role=admin
   profile.
|#

; we'll use a global counter for UID
(define UID 0)
(define KEY (crypto-random-bytes 16))

; parse-cookie : string -> hash
;; parses a cookie into a hash
(define (parse-cookie cookie)
  (make-weak-hash (map (λ (s) (string-split s "="))
                  (string-split cookie "&"))))

; profile-for : string -> string
;; encodes a user profile as a cookie
(define (profile-for email)
  (set! UID (add1 UID))
  (string-append "email=" (string-replace email #rx"[&=]+" "")
                 "&uid=" (number->string UID)
                 "&role=user"))

; encrypt-profile : string -> bytes
;; encrypt a profile for a user given the email
(define (encrypt-profile email)
  (aes-128-encrypt
   (pkcs7-pad (string->bytes/utf-8 (profile-for email)))
   KEY))

; decrypt-profile : bytes -> hash
;; decrypt a user profile
(define (decrypt-profile prof)
  (parse-cookie
   (bytes->string/utf-8
    (pkcs7-unpad (aes-128-decrypt prof KEY)))))

; create-admin-profile : void -> hash
; creates a fake admin profile using cut and paste attack
(define (create-admin-profile)
    ; This attack involves block alignment.
    ; 
    ; 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    ; email=sponge@bob .com&uid=2&role= user
    ; email=blahblahbl adminBBBBBBBBBBB &uid=3&role=user
    ; Cut and paste the blocks you want
    ; email=spongebobs quar&uid=2&role= admin0000000000B
  (define first-entry (encrypt-profile "sponge@bob.com"))
  (define second-entry (encrypt-profile
                        (bytes->string/utf-8
                         (bytes-append #"blahblahbladmin"
                                       (make-bytes 11 11)))))
  (decrypt-profile
   (bytes-append (subbytes first-entry 0 32)
                 (subbytes second-entry 16 32))))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (define helpers
    (test-suite
     "Helpers"
     (check-equal? (parse-cookie "foo=bar&baz=qux&zap=zazzle")
                   (make-weak-hash
                    (list                            
                     (list "foo" "bar")
                     (list "baz" "qux")
                     (list "zap" "zazzle"))))
     (check-equal? (profile-for "foo@bar.com")
                   "email=foo@bar.com&uid=1&role=user")
     (check-equal? (profile-for "foo&user=admin@bar.com")
                   "email=foouseradmin@bar.com&uid=2&role=user")))
     (define challenge-13
       (test-suite
        "Challenge 13"
        helpers
        (check-equal? (hash-ref (create-admin-profile) "role")
                      (list "admin"))))
  (time-test challenge-13))
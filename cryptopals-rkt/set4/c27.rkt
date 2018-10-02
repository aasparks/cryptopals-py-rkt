#lang racket

; Challenge 27
;; Recover the key from CBC with IV=key
(require racket/random
         "../aes/aes.rkt"
         "../set1/c2.rkt"
         "../set2/c9.rkt")

#|
   Take your code from exercise 16 and modify it so that it repurposes the key
   for CBC encryption as the IV.
|#
(define KEY (crypto-random-bytes 16))

;; Encryption function
; encryption-oracle : bytes -> bytes
;; sanitizes, appends, and prepends the set byte strings,
;; and encrypts the input under a secret key
(define (encryption-oracle txt)
  (define sanitized
    (list->bytes
     (remove #\;
             (remove #\= (bytes->list txt)))))
  (aes-128-cbc-encrypt (pkcs7-pad sanitized)
                       KEY
                       KEY)) ; IV=KEY

#|
   Applications sometimes use the key as an IV on the auspices that both the sender and the
   receiver have to know the key already, and can save some space by using it as both a
   key and an IV.

   Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get
   the receiver to decrypt a value that will reveal the key.

   The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for
   ASCII compliance. Noncomplaint messages should raise an exception or return an error that
   includes the decrypted plaintext (this happens all the time in real systems, for what it's
   worth).
|#

; verify-url bytes -> bytes
;; verify that the url contains no bytes >= 128
(define (verify-url pt)
  (if (andmap (λ (b)
                (< b 128))
              (bytes->list pt))
      pt
      ; raise allows you to raise any value and not
      ; just an exn? struct
      (raise pt)))

#|
   Use your code to encrypt a message that is 3 blocks long:
    AES-CBC(P1, P2, P3) -> C1, C2, C3
|#
(define chorus #"hej hej monika, hej pa de monika\n")
(define verse1 #"kalla blickar, kalla karar\ndu var bara 14 varar\n")
(define verse2 #"ta min hand och visa mig vagen\njag ar din i alla lagen\n")
(define MSG (bytes-append chorus chorus chorus chorus verse1 verse2))
(define CT (encryption-oracle MSG))

#|
   Modify the message (you are now the attacker):
    C1, C2, C3 -> C1, C0, C1
|#
(define EVIL-CT (bytes-append (get-block CT 0)
                              (make-bytes 16 0)
                              (get-block CT 0)))

#|
   Decrypt the message (you are now the receiver) and raise the
   appropriate error if high-ASCII is found.
|#
; decryption-oracle : bytes -> bytes
;; decrypts the given ct and verfies the url
(define (decryption-oracle ct)
  (verify-url (aes-128-cbc-decrypt ct KEY KEY)))

#|
   As the attacker, recovering the plaintext from the, extract the key:
    P'1 XOR P'3
|#
; verify-attack : bytes -> bytes
;; runs the attack on CTR as described
(define (verify-attack ct)
  (with-handlers ([bytes?
                   (λ (EVIL-PT)
                     (define found-key
                       (xorstrs (get-block EVIL-PT 0)
                                (get-block EVIL-PT 2)))
                     (pkcs7-unpad
                      (aes-128-cbc-decrypt CT found-key found-key)))])
    (decryption-oracle ct)))



(module+ test
  (require rackunit)

  (check-equal? (verify-url #"https://www.google.com")
                #"https://www.google.com")
  (check-exn
   bytes?
   (λ ()
     (verify-url #"www.goågle.com")))

  (check-equal? MSG (verify-attack EVIL-CT)))
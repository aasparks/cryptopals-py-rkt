#lang racket/base

;;;;;; SWITCH TO SHA1

; Challenge 42
;; Bleichenbacher's e=3 RSA Attack
(require sha
         racket/list
         "../util/rsa.rkt"
         "../util/conversions.rkt"
         "../set5/c40.rkt"
         "../util/pkcs1.5.rkt")

(provide pkcs15-verify-bad
         forge-sig)

(define DEBUG #true)

#|
   RSA with an encrypting exponent of 3 is popular,
   because it makes the RSA math faster.

   With e=3 RSA, encryption is just cubing a number
   mod the public encryption modulus:
      c = m**3 % n

   e=3 is secure as long as we can make assumptions about
   the message blocks we're encrypting. The worry with low-
   exponent RSA is that the message blocks we process won't
   be large enough to wrap the modulus after being cubed.
   The block 00:02 (imagine sufficient zero-padding) can
   be "encrypted" in e=3 RSA; it is simple 00:08.

   When RSA is used to sign, rather than encrypt, the
   operations are reversed; the verifier "decrypts" the
   message by cubing it. This produces a "plaintext"
   which the verifier checks for validity.

   When you use RSA to sign a message, you supply it
   a block input that contains a message digest. The
   PKCS1.5 standard formats that block as:
      00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH

   As intended, the ffh bytes in that block expand to
   fill the whole block, producing a "right-justified"
   hash (the last byte of the hash is the last byte of
   the message)

   There was, 7 years ago, a common implementation flaw
   with RSA verifiers: they'd verify signatures by
   "decrypting" them (cubing them modulo the public
   exponent) and then "parsing" them by looking for
   00h 01h ... ffh 00h ASN.1 HASH.

   This is a bug because it implies the verifier isn't
   checking all the padding. If you don't check the
   padding, you leave open the possibility that instead
   of hundreds of ffh bytes, you have only a few, which
   if you think about it means there could be squizzilions
   of possible numbers that could produce a valid-looking
   signature.

   How to find such a block? Find a number that when cubed
   (a) doesn't wrap the modulus (thus bypassing the key
   entirely) and (b) produces a block that starts
   "00h 01h ffh ... 00h ASN.1 HASH"

   There are two ways to approach this problem:
      * You can work from Hal Finney's writeup,
        available on Google, of how Bleichenbacher
        explained the math "so that you can do it by
        hand with a pencil"
      * You can implement an integer cube root in your
        language, format the message block you want to
        forge, leaving sufficient trailing zeros at the
        end to fill with garbage, then take the cube-root
        of that block.

   Forge a 1024-bit RSA signature for the string "hi mom"

   Make sure your implmentation actually accepts the signature!
|#

; pkcs15-verify-bad : bytes? bytes? (cons/c integer? integer?)
;; verifies PKCS1.5 signature in an insecure way
(define (pkcs15-verify-bad msg sig pub)
  (define m (rsa-decrypt sig pub))
  ; NB: I SUCK at writing regexp. I wish I didn't.
  (define rx
    (string-append "[00][01][ff]+[00]"
                   "[3021300906052b0e03021a05000414]"
                   ".*"))
  (define valid
    (regexp-match? (regexp rx)
                   (ascii->hex m)))
  (cond
    [valid (define split (regexp-split "3021300906052b0e03021a05000414"
                                       (ascii->hex m)))
           
           (define h (subbytes (hex->ascii (second split)) 0 20))
           (bytes=? (sha1 msg) h)]
    [else #false]))

; forge-sig : bytes? -> bytes?
;; generates a valid signature for the bad verifier
(define (forge-sig msg)
  (define asn #"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14")
  (integer->bytes
   (add1 ; nth-root takes the floor and i guess we want ceiling
    (nth-root
     (bytes->integer
      (bytes-append
       #"\x00\x01\xff\x00"
       asn
       (sha1 msg)
       (make-bytes (- 128 4 (bytes-length asn) 20) 0)))
     3))))

(module+ test
  (require rackunit
           "../util/test.rkt")

  (define-values (pub priv) (rsa-keygen))
  (define msg #"hi mom")
  (define sig (pkcs15-sign msg priv))
  (define fsig (forge-sig msg))
  
  (define challenge-42
    (test-suite
     "Challenge 42"
     (check-true (pkcs15-verify-bad msg sig pub))
     (check-true (pkcs15-verify-bad msg fsig pub))
     (check-exn exn:fail?
                (λ () (pkcs15-verify msg fsig pub)))
     (check-true (pkcs15-verify msg sig pub))))

  (time-test challenge-42))
#lang racket/base

(require sha
         math/number-theory
         "conversions.rkt")

(provide pkcs15-sign
         pkcs15-verify)
;; RSASSA-PKCS1-v1_5

;; My own implementation of PKCS1 v1.5 for signature
;; generation.

;;; RSASSA-PKCS1-v1_5 combines the RSASP1 and RSAVP1
;;; primitives with the EMSA-PKCS1-v1_5 encoding method.
;;;; (can we talk about how long these acronyms are?)


; Signature generation operation
;; Input:
;; K signer's RSA private key
;; M message to be signed, an octet string
;; Output:
;; S signature, an octet string of length k, where
;;   k is the length in octets of the RSA modulus n
;; Errors:
;; "message too long"
;; "RSA modulus too short"
; pkcs15-sign : bytes? (cons/c integer? integer?)
;; Signs the message using PKCS1 v1.5 RSA signature gen
(define (pkcs15-sign m priv)
  (define k (bytes-length (integer->bytes (cdr priv))))
  ; 1. EMSA-PKCS1-v1_5 encoding
  (define em (emsa-pkcs15-encode m k))
  ; 2. a. Convert message to integer message
  ; 2. b. Apply RSASP1 signature primitive to the
  ;       RSA private key K and the message
  ;       representative m to produce integer
  ;       signature representative s:
  ;       s = RSASP1(k,m)
  (define s (RSASP1 (bytes->integer em) priv))
  ; 2. c. Convert signature s to signature S of
  ;       length k octets
  ; 3. Output the signature S
  (integer->bytes s k))

; Signature verification
;; Input:
;; (n,e) signer's RSA public key
;; M message whose signature is to be verified
;; S signature to be verified, octet of length k
;; Output:
;; "valid signature" or "invalid signature"
;; Errors:
;; "message too long"
;; "RSA modulus too short"
(define (pkcs15-verify msg sig pub)
  (define k (bytes-length (integer->bytes (cdr pub))))
  (unless (= k (bytes-length sig))
    (error 'verify "invalid signature"))
  (define s (bytes->integer sig))
  (define m (RSAVP1 s pub))
  (define em (integer->bytes m k))
  (define em-prime (emsa-pkcs15-encode msg k))
  (bytes=? em em-prime))

; emsa-pkcs15-encode : bytes? integer?
;; Encodes and pads the message according to EMSA
(define (emsa-pkcs15-encode msg em-len)
  (define h (sha1 msg))
  (define der #"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14")
  (define T (bytes-append der h))
  (define t-len (bytes-length T))
  (when (< em-len (+ t-len 11))
    (error 'emsa-pkcs15 "intended encoded message length too short"))
  (define ps (make-bytes (- em-len t-len 3) #xff))
  (bytes-append #"\x00\x01" ps #"\x00" T))

; RSASP1
;; Input:
;;  K RSA private key (d,n)
;;  m message representative
;; Output:
;;  s signature representative, an integer between 0 and n-1
;; Error:
;;  "messages representative out of range"
; RSASP1 : integer? (cons/c integer? integer?)
;; Applies the RSA signature primitive to the RSA
;; private key and the message representative to produce
;; an integer representative
(define (RSASP1 m priv)
  (when (or (> m (sub1 (cdr priv)))
            (< m 0))
    (error 'RSASP1 "message representative out of range"))
  (modular-expt m (car priv) (cdr priv)))

; RSAVP1 : integer? (cons/c integer? integer?) -> integer?
;; generates signature representative
(define (RSAVP1 s pub)
  (unless (and (>= s 0) (< s (cdr pub)))
    (error 'rsasvp1 "signature representative out of range"))
  (modular-expt s (car pub) (cdr pub)))


(module+ test
  (require rackunit
           "test.rkt")

  ; Tests come from FIPS 186-2 Test vectors

  ; mod size 1024
  (define n
    (bytes->integer
     (hex->ascii
      (bytes-append
       #"c8a2069182394a2ab7c3f4190c15589c56"
       #"a2d4bc42dca675b34cc950e24663048441"
       #"e8aa593b2bc59e198b8c257e882120c623"
       #"36e5cc745012c7ffb063eebe53f3c6504c"
       #"ba6cfe51baa3b6d1074b2f398171f4b198"
       #"2f4d65caf882ea4d56f32ab57d0c44e6ad"
       #"4e9cf57a4339eb6962406e350c1b153971"
       #"83fbf1f0353c9fc991"))))
  (define e ; my bytes->integer should ignore leading 0s but i guess it doesn't matter
    (bytes->integer
     (hex->ascii
      (bytes-append
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"0000000000000000000000000000000000"
       #"000000000000010001"))))
  (define d
    (bytes->integer
     (hex->ascii
      (bytes-append
       #"5dfcb111072d29565ba1db3ec48f57645"
       #"d9d8804ed598a4d470268a89067a2c921"
       #"dff24ba2e37a3ce834555000dc868ee65"
       #"88b7493303528b1b3a94f0b71730cf1e8"
       #"6fca5aeedc3afa16f65c0189d810ddcd8"
       #"1049ebbd0391868c50edec958b3a2aaef"
       #"f6a575897e2f20a3ab5455c1bfa55010a"
       #"c51a7799b1ff8483644a3d425"))))

  ; Tests
  (define mod-1024
    (test-suite
     "Mod size 1024"
     (check-equal?
      (ascii->hex
       (pkcs15-sign
        (hex->ascii
         (bytes-append
          #"e8312742ae23c456ef28a23142"
          #"c4490895832765dadce02afe5b"
          #"e5d31b0048fbeee2cf218b1747"
          #"ad4fd81a2e17e124e6af17c388"
          #"8e6d2d40c00807f423a233cad6"
          #"2ce9eaefb709856c94af166dba"
          #"08e7a06965d7fc0d8e5cb26559"
          #"c460e47bc088589d2242c9b3e6"
          #"2da4896fab199e144ec136db8d"
          #"84ab84bcba04ca3b90c8e5"))
        (cons d n)))
      (bytes-append
       #"28928e19eb86f9c00070a59edf6bf843"
       #"3a45df495cd1c73613c2129840f48c4a"
       #"2c24f11df79bc5c0782bcedde97dbbb2a"
       #"cc6e512d19f085027cd575038453d04905"
       #"413e947e6e1dddbeb3535cdb3d8971fe020"
       #"0506941056f21243503c83eadde053ed866"
       #"c0e0250beddd927a08212aa8ac0efd61631"
       #"ef89d8d049efb36bb35f"))
     (check-true
      (pkcs15-verify
       (hex->ascii
         (bytes-append
          #"e8312742ae23c456ef28a23142"
          #"c4490895832765dadce02afe5b"
          #"e5d31b0048fbeee2cf218b1747"
          #"ad4fd81a2e17e124e6af17c388"
          #"8e6d2d40c00807f423a233cad6"
          #"2ce9eaefb709856c94af166dba"
          #"08e7a06965d7fc0d8e5cb26559"
          #"c460e47bc088589d2242c9b3e6"
          #"2da4896fab199e144ec136db8d"
          #"84ab84bcba04ca3b90c8e5"))
       (pkcs15-sign
        (hex->ascii
         (bytes-append
          #"e8312742ae23c456ef28a23142"
          #"c4490895832765dadce02afe5b"
          #"e5d31b0048fbeee2cf218b1747"
          #"ad4fd81a2e17e124e6af17c388"
          #"8e6d2d40c00807f423a233cad6"
          #"2ce9eaefb709856c94af166dba"
          #"08e7a06965d7fc0d8e5cb26559"
          #"c460e47bc088589d2242c9b3e6"
          #"2da4896fab199e144ec136db8d"
          #"84ab84bcba04ca3b90c8e5"))
        (cons d n))
       (cons e n)))
     (check-equal?
      (ascii->hex
       (pkcs15-sign
        (hex->ascii
         (bytes-append
         #"207102f598ec280045be67592f5bba25"
         #"ba2e2b56e0d2397cbe857cde52da8cca"
         #"83ae1e29615c7056af35e8319f2af86f"
         #"dccc4434cd7707e319c9b2356659d7886"
         #"7a6467a154e76b73c81260f3ab443cc03"
         #"9a0d42695076a79bd8ca25ebc8952ed44"
         #"3c2103b2900c9f58b6a1c8a6266e43880"
         #"cda93bc64d714c980cd8688e8e63"))
        (cons d n)))
      (bytes-append
       #"77f0f2a04848fe90a8eb35ab5d94cae843db"
       #"61024d0167289eea92e5d1e10a526e420f2d"
       #"334f1bf2aa7ea4e14a93a68dba60fd2ede58"
       #"b794dcbd37dcb1967877d6b67da3fdf2c0c7"
       #"433e47134dde00c9c4d4072e43361a767a52"
       #"7675d8bda7d5921bd483c9551950739e9b2b"
       #"e027df3015b61f751ac1d9f37bea3214d3c8dc96"))
     (check-true
      (pkcs15-verify
       (hex->ascii
         (bytes-append
         #"207102f598ec280045be67592f5bba25"
         #"ba2e2b56e0d2397cbe857cde52da8cca"
         #"83ae1e29615c7056af35e8319f2af86f"
         #"dccc4434cd7707e319c9b2356659d7886"
         #"7a6467a154e76b73c81260f3ab443cc03"
         #"9a0d42695076a79bd8ca25ebc8952ed44"
         #"3c2103b2900c9f58b6a1c8a6266e43880"
         #"cda93bc64d714c980cd8688e8e63"))
       (pkcs15-sign
        (hex->ascii
         (bytes-append
         #"207102f598ec280045be67592f5bba25"
         #"ba2e2b56e0d2397cbe857cde52da8cca"
         #"83ae1e29615c7056af35e8319f2af86f"
         #"dccc4434cd7707e319c9b2356659d7886"
         #"7a6467a154e76b73c81260f3ab443cc03"
         #"9a0d42695076a79bd8ca25ebc8952ed44"
         #"3c2103b2900c9f58b6a1c8a6266e43880"
         #"cda93bc64d714c980cd8688e8e63"))
        (cons d n))
       (cons e n)))))

  (time-test mod-1024))
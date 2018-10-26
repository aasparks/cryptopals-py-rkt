#lang racket

; Challenge 35
;; Implement DH with Negotiated Groups, and
;; Break With Malicious "g" Parameters
(require racket/random
         racket/async-channel
         "../util/diffie-hellman.rkt"
         "../util/conversions.rkt"
         "../util/aes.rkt"
         "../util/pkcs7.rkt")

(define DEBUG #false)

#|
   A->B
     Send "p", "g"
   B->A
     Send ACK
   A->B
     Send "A"
   B->A
     Send "B"
   A->B
     Send AES-CBC(SHA1(s)[0:16],iv=random(16),msg)+iv
   B->A
     Send AES-CBC(SHA1(s)[0:16],iv=random(16), A's msg)+iv

   Do the MITM attack again, but play with "g".
   What happens with:
     g = 1
     g = p
     g = p - 1

   Write atacks for each.
|#
; alice : async-channel async-channel (listof bytes) integer integer
;; simulates communication with bob via async channels, using
;; supplied values for p and g
(define (alice to-bob from-bob msgs p g)
  (thread
   (λ ()
     ; A->B Send p,g
     (async-channel-put to-bob (list p g))
     ; B->A Send ACK
     (define ack (async-channel-get from-bob))
     (when (not (equal? ack "ACK"))
       (error 'alice "did not receive proper ACK\n"))
     ; A->B Send A
     (define-values (a A) (diffie-hellman p g))
     (async-channel-put to-bob A)
     ; B->A Send B
     (define B (async-channel-get from-bob))
     (when DEBUG
       (printf "ALICE: B: ~v\n" B))
     (define session-key (make-session-key B a p))
     (define key (subbytes session-key 0 16))
     (when DEBUG
       (printf "ALICE: KEY: ~v\n" (ascii->hex key)))
     (map (λ (msg)
            ; A->B Send AES-CBC(key,iv,msg) + iv
            (define iv (crypto-random-bytes 16))
            (define enc-msg (aes-128-encrypt
                             (pkcs7-pad msg)
                             key iv #:mode 'cbc))
            (when DEBUG
              (printf "ALICE: msg: ~v\n" msg))
            (async-channel-put to-bob (bytes-append iv enc-msg))
            ; B->A Send AES-CBC(key,iv,msg) + iv
            (define echo (async-channel-get from-bob))
            (when (not echo) (error 'alice "no echo from bob"))
            (define dec-echo (decryption-oracle echo key))
            (when DEBUG
              (printf "ALICE: echo: ~v\n" dec-echo))
            (when (not (equal? dec-echo msg)) (error 'alice "wrong echo from bob"))
            (void))
          msgs))))

; bob : async-channel async-channel
;; simulates communication with alice
(define (bob to-alice from-alice)
  (thread
   (λ ()
     ; A->B Send p,g
     (define-values (p g) (apply values (async-channel-get from-alice)))
     (when DEBUG
       (printf "BOB: (p g) = (~v ~v)\n" p g))
     ; B->A Send ACK
     (async-channel-put to-alice "ACK")
     ; A->B Send A
     (define A (async-channel-get from-alice))
     (when DEBUG
       (printf "BOB: A: ~v\n" A))
     ; B->A Send B
     (define-values (b B) (diffie-hellman p g))
     (async-channel-put to-alice B)
     (define session-key (make-session-key A b p))
     (define key (subbytes session-key 0 16))
     (when DEBUG
       (printf "BOB: key: ~v\n" (ascii->hex key)))
     (let loop ()
       ; A->B Send AES-CBC(txt,key,iv) + iv
       (define enc-msg (sync/timeout 0.5 from-alice))
       (when enc-msg
         (define msg (decryption-oracle enc-msg key))
         (define iv (crypto-random-bytes 16))
         (define echo
           (aes-128-encrypt
            (pkcs7-pad msg)
            key iv #:mode 'cbc))
         (async-channel-put to-alice (bytes-append iv echo))
         (loop))))))

; mallory : async-channel async-channel async-channel async-channel
(define (mallory to-alice to-bob from-alice from-bob)
  ; A->M Send p,g
  (define-values (p g) (apply values (async-channel-get from-alice)))
  ; M->B Send p,g
  (async-channel-put to-bob (list p g))
  ; B->A Send ACK
  (async-channel-put to-alice (async-channel-get from-bob))
  ; A->B Send A
  (define A (async-channel-get from-alice))
  (async-channel-put to-bob A)
  ; B->A Send B
  (define B (async-channel-get from-bob))
  (async-channel-put to-alice B)
  (define session-key (make-session-key g 1 p))
  ; for g=p-1, the key can be either 1 or p-1
  ; depending on whether a/b is even or odd
  (define alt-session-key (make-session-key g 2 p))
  (define key (subbytes session-key 0 16))
  (define alt-key (subbytes alt-session-key 0 16))
  (when DEBUG
    (printf "MALLORY: KEY: ~v\n" (ascii->hex key)))
  ; A->B Send AES-CBC(msg,key,iv) + iv
  (let loop ()
    (define enc-msg (sync/timeout 0.3 from-alice))
    (if enc-msg
        (begin
          (async-channel-put to-bob enc-msg)
          (async-channel-put to-alice (async-channel-get from-bob))
          (cons
           (with-handlers ([exn:fail?
                            (λ (e) (decryption-oracle enc-msg alt-key))])
             (decryption-oracle enc-msg key))
           (loop)))
        empty)))

;; just to keep the code clean
(define (decryption-oracle txt key)
  (pkcs7-unpad
   (aes-128-decrypt
    (subbytes txt 16)
    key #:mode 'cbc
    (subbytes txt 0 16))))

(module+ test
  (require rackunit)

  (define p (string->number
             (string-append
              "#xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
              "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
              "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
              "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
              "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
              "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
              "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
              "fffffffffffff")))
  ; msgs for alice to send
  (define msgs
    (list #"Say, you're good."
          #"Thanks."
          #"Ha! Darn."
          #"Mary had a little lamb whose fleece was white as...PICKLED FISH LIPS!"
          #"eep!"
          #"Sea weavle."
          #"Gorgy smorgy."
          #"At least I'm safe inside my mind."
          #"Gahhh!"))

  ; run-MITM : integer -> void
  ;; runs the man-in-the-middle attack with the
  ;; specified g value
  (define (run-MITM new-g)
    (define to-alice (make-async-channel))
    (define to-bob (make-async-channel))
    (define from-alice (make-async-channel))
    (define from-bob (make-async-channel))
    (define a-thread
      (alice from-alice to-alice msgs p new-g))
    (define b-thread
      (bob from-bob to-bob))
    (define eves (mallory to-alice to-bob from-alice from-bob))
    (thread-wait a-thread)
    (thread-wait b-thread)
    (check-equal? eves msgs))
  
  ; i'm defining p so i don't have to rewrite
  ; mallory. mallory knows p so this seems fair.
  
  ; g = 1
  (run-MITM 1)
  
  ; g = p
  (run-MITM p)
  
  ; g = p - 1
  (run-MITM (sub1 p)))

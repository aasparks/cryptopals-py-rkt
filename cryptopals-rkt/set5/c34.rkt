#lang racket

; Challenge 34
;; Implement a MITM Key-Fixing Attack
;; on Diffie-Hellman with Parameter Injection
(require racket/random
         "c33.rkt"
         "../set1/c1.rkt"
         "../aes/aes.rkt"
         "../set2/c9.rkt")

(define DEBUG #false)

#|
   Use the code you just worked out to build a
   protocol and an "echo" bot. You don't actually
   have to do the network part of this if you don't
   want; just simulate that. The protocol is:
     A->B
       Send "p", "g", "A"
     B->A
       Send "B"
     A->B
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     B->A
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
   (In other words, derive an AES key from DH with SHA1, use it
   in both directions, and do CBC with random IVs appended or
   prepended to the message.
|#
; alice -> channel channel (listof bytes) -> void
;; simulates alice by sending the list of messages
;; to the receiver and getting the values echo'd back
;; by the sender. Without MITM, sender == receiver.
(define (alice sender receiver messages)
  (thread
   (λ ()
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
     (define g 2)
     (define-values (a A) (diffie-hellman p g))
     #;(when DEBUG
       (printf "ALICE: a: ~v A: ~v\n" a A))
     (channel-put receiver (list p g A))
     (define B (channel-get sender))
     #;(when DEBUG
       (printf "ALICE: B: ~v\n" B))
     (define session-key (make-session-key B a p))
     (define key (subbytes session-key 0 16))
     #;(when DEBUG
       (printf "ALICE: key: ~v\n" (ascii->hex key)))
     (map (λ (msg)
            (when DEBUG
              (printf "ALICE: msg: ~v\n" msg))
            ; encrypt the message and send it
            (define iv (crypto-random-bytes 16))
            (define e-msg (bytes-append
                           iv
                           (aes-128-cbc-encrypt (pkcs7-pad msg) key iv)))
            (channel-put receiver e-msg)
            ; receive the echo and decrypt it
            (define echo (channel-get sender))
            (define d-echo (pkcs7-unpad
                            (aes-128-cbc-decrypt
                             (subbytes echo 16) ; msg
                             key
                             (subbytes echo 0 16)))) ; iv
            ; verify equality just because
            (when (not (equal? msg d-echo))
              (error 'alice
                     "The echo ~v did not match the msg ~v\n"
                     d-echo msg))
            (when DEBUG
              (printf "ALICE: echo: ~v\n" d-echo)))
          messages)
     (void))))

; bob : channel channel -> void
;; simulates bob by echoing messages from alice
(define (bob sender receiver)
  (thread
   (λ ()
     (define-values (p g A) (apply values (channel-get sender)))
     #;(when DEBUG
       (printf "BOB: p: ~v\ng: ~v\nA: ~v\n" p g A))
     (define-values (b B) (diffie-hellman p g))
     (channel-put receiver B)
     #;(when DEBUG
       (printf "BOB: B: ~v\n" B))
     (define session-key (make-session-key A b p))
     (define key (subbytes session-key 0 16))
     #;(when DEBUG
       (printf "BOB: key: ~v\n" (ascii->hex key)))
     (let loop ()
       (define iv (crypto-random-bytes 16))
       (define e-msg (sync/timeout 3 sender))
       (when e-msg
         (define msg (pkcs7-unpad
                      (aes-128-cbc-decrypt
                       (subbytes e-msg 16) ; msg
                       key
                       (subbytes e-msg 0 16))))
         (define echo (bytes-append
                       iv
                       (aes-128-cbc-encrypt (pkcs7-pad msg) key iv)))
         (channel-put receiver echo)
         (loop)) ; loop until messages stop
       (void)))))

#|
   Now implement the following MITM attack:
     A->M
       Send "p", "g", "A"
     M->B
       Send "p", "g", "p"
     B->M
       Send "B"
     M->A
       Send "p"
     A->M
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     M->B
       Relay that to B
     B->M
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     M->A
       Relay that to A

   M should be able to decrypt the messages. "A" and "B"
   in the protocol ---the public keys, over the wire ---
   have been swapped out with "p". Do the DH math on this
   quickly to see what that does to the predictability of
   the key.

   Decrypt the messages from M's vantage point as they go
   by.

   Note that you don't actually have to inject bogus paramaters
   to make this attack work; you could just generate Ma, MA,
   Mb, and MB as valid DH parameters to do a generic MITM attack.
   But do the parameter injection attack; it's going to come
   up again.
|#

; mallory : channel channel -> (listof bytes)
;; simulates mallory by executing the MITM attack
;; and returning all the messages alice sent
(define (mallory alice bob from-alice from-bob)
  ; A->M p,g,A
  (define-values (p g A) (apply values (channel-get from-alice)))
  (channel-put bob (list p g p)) ; M->B p,g,p
  (define B (channel-get from-bob)) ; B->M B
  (channel-put alice p) ; M->A p
  ;; It took me a minute to figure out how to get the key.
  ;; The temptation to Google was strong but I resisted.
  ;; Turns out, it's really obvious if you write it down.
  ;; They both call (session-key p a/b p) 
  ;; Since you don't know a or b, how do you get the key?
  ;; session-key does the following operation:
  ;;   (B**a) % p or (A**b) % p
  ;; =>(p**a) % p or (p**b) % p
  ;; => p or p
  ;; So you can pass any value to make-session-key
  (define key
    (subbytes (make-session-key p 1 p) 0 16))
  ;; receive messages infinitely from both alice and bob
  ;; and send to the other one
  (let loop ()
    (define a-msg (sync/timeout 0.1 from-alice))
    (if a-msg
        (begin
          (channel-put bob a-msg)
          (let ([msg (pkcs7-unpad
                      (aes-128-cbc-decrypt
                       (subbytes a-msg 16) ; msg
                       key
                       (subbytes a-msg 0 16)))]
                [b-msg (sync/timeout 0.1 from-bob)])
            (channel-put alice b-msg)
            (cons msg (loop))))
        empty)))

(module+ test
  (require rackunit)

  (define alice-ch (make-channel))
  (define bob-ch (make-channel))
  ; should not throw any exceptions
  (define alice-thread-1
    (alice alice-ch bob-ch
           (list #"hey bob"
                 #"how are you?"
                 #"stop copying me!")))
  (define bob-thread-1
    (bob bob-ch alice-ch))
  (thread-wait alice-thread-1)
  (thread-wait bob-thread-1)

  ; now run the mitm attack
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
  ; i need four channels for this
  (define to-alice (make-channel))
  (define to-bob (make-channel))
  (define from-bob (make-channel))
  (define from-alice (make-channel))
  (define alice-thread-2
    (alice to-alice from-alice msgs))
  (define bob-thread-2
    (bob to-bob from-bob))
  (check-equal? (mallory to-alice to-bob from-alice from-bob)
                msgs)
  (thread-wait alice-thread-2)
  (thread-wait bob-thread-2))
#lang racket

; Challenge 36
;; Implement Secure Remote Password (SRP)
(require racket/random
         math/number-theory
         sha
         "../set1/c1.rkt"
         "../set4/c31.rkt")

(define hmac-sha1 hmac)
(define DEBUG #false)

; bstr->integer : bytes -> integer
;; convert a byte string of any length to
;; an integer
(define (bstr->integer b)
  (string->number (bytes->string/utf-8 b)))

; integer->bstr : integer -> bytes
;; convert a large integer to a byte string
(define (integer->bstr num)
  (string->bytes/utf-8 (number->string num)))

#|
   To understand SRP, look at how you generate an AES
   key from DH; now, just observe you can do the
   "opposite" operation and generate a numeric
   parameter from a hash. Then:
   Replace A and B with C and S (client and server)

   C&S
     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
|#
(define SRPServer%
  (class object%

    ; init with agreed-upon values and valid credentials.
    ; credentials is a list of pairs (I,P)
    (init-field N g k credentials)
    ; db is a hash that maps from I to
    ; to the pair (salt,v)
    (define db (make-hash))
    ; save the thread for listening
    (define listening-thread (void))
    (super-new)

    #|
       S
         1. Generate salt as a random integer
         2. Generate string xH=SHA256(salt || password)
         3. Convert xH to integer x somehow (put 0x on hexdigest)
         4. Generate v= g**x % N
         5. Save everything but x, xH
    |#

    ; generate password table from credentials
    (map (λ (cred)
           (define salt (crypto-random-bytes 8))
           (define xH
             (sha-1 (bytes-append salt (second cred))))
           (define x (bstr->integer (bytes-append #"#x" (ascii->hex xH))))
           (define v (modular-expt g x N))
           (hash-set! db (first cred) (list salt v)))
         credentials)

    ; start-listening : port? port? -> void
    ;; begins listening for messages on the input-port
    (define/public (start-listening in out)
      (when (is-listening?)
        (error 'start-listening
               "Server is already listening"))
      #|
   C->S
     Send I, A=g**a % N (a la Diffie-Hellman)
   S->C
     Send salt, B = kv + g**b % N
   S,C
     Compute string uH = SHA256(A || B), u = integer of uH
   C
     1. Generate string xH = SHA256(salt || password)
     2. Convert xH to integer x somehow
     3. Generate S = (B-k * g**x)**(a + u*x) % N
     4. Generate K = SHA256(S)
   S
     1. Generate S = (A * v**u)**b % N
     2. Generate K = SHA256(S)
   C->S
     Send HMAC-SHA256(K, salt)
   S->C
     Send "OK" if HMAC-SHA256(K, salt) validates
|#
      (set! listening-thread
        (thread
         (λ ()
           (let loop ()
             ; C->S I,A
             (define-values (I A)
               (apply values (channel-get in)))
             ; S->C salt,B
             (define-values (salt v)
               (apply values (hash-ref db I)))
             (define b (integer-bytes->integer
                        (crypto-random-bytes 8) #f))
             (when DEBUG
               (printf "b: ~v\n" b))
             (define B (+  (* k v)
                           (modular-expt g b N)))
             (channel-put out (list salt B))
             ; S,C compute uH
             (define uH
               (sha-1
                (bytes-append
                 (integer->bstr A)
                 (integer->bstr B))))
             ; S Generate S, K
             (define u (bstr->integer (bytes-append #"#x" (ascii->hex uH))))
             (define S
               (modular-expt (* A (modular-expt v u N))
                             b
                             N))
             (define K (sha-1 (integer->bstr S)))
             ; C->S HMAC-SHA256(k, salt)
             (define actual (channel-get in))
             (define expected (hmac-sha1 K salt))
             (if (equal? actual expected)
                 (channel-put out 'ok)
                 (channel-put out 'bad))
             (loop))))))

    ; stop-listening : void -> void
    ;; stops listening for new messages
    (define/public (stop-listening)
      (kill-thread listening-thread))

    ; is-listening? : void -> boolean
    ;; determines if the server is already listening
    (define/private (is-listening?)
      (thread? listening-thread))))

#|

   You're going to want to do this at a REPL of some sort;
   it may take a couple of tries.

   It doesn't matter how you go from integer to string or string
   to integer (where things are going in or out of SHA256) as long
   as you do it consistently. I tested by using the ASCII decimal
   representation of integers as input to SHA256, and by converting
   the hexdigest to an integer when processing its output.

   This is basically Diffie-Hellman with a tweak of mixing the password
   into the public keys. The server also takes an extra step to avoid
   storing an easily crackable password-equivalent.
|#
(define SRPClient%
  (class object%
    ; init with same values as server
    (init-field N g k in out)
    (super-new)

    ; authenticate-user : bytes bytes -> boolean
    ;; communicates with the server to authenticate a
    ;; session under the given email.
    (define/public (authenticate-user email password)
      ; C->S I,A
      (define a (integer-bytes->integer
                 (crypto-random-bytes 8) #f))
      (when DEBUG
        (printf "a: ~v\n" a))
      (define A (modular-expt g a N))
      (when DEBUG
        (printf "A: ~v\n" A))
      (channel-put out (list email A))
      ; S->C salt,B
      (define-values (salt B)
        (apply values (channel-get in)))
      (when DEBUG
        (printf "B: ~v\n" B)
        (printf "Salt: ~v\n" salt))
      ; S,C Compute uH
      (define uH
        (sha-1
         (bytes-append
          (integer->bstr A)
          (integer->bstr B))))
      (define u (bstr->integer (bytes-append #"#x" (ascii->hex uH))))
      ; C generate xH,x,S,K
      (define xH (sha-1
                  (bytes-append salt password)))
      (define x (bstr->integer (bytes-append #"#x" (ascii->hex xH))))
      (define S
        (modular-expt
         (* (- B k)
           (modular-expt g x N))
         (+ a (* u x))
         N))
      (define K (sha-1 (integer->bstr S)))
      ; C->S HMAC-SHA256(k, salt)
      (channel-put out (hmac-sha1 K salt))
      (define result (channel-get in))
      (equal? result 'ok))))

; Test simple usage
(module+ test
  (require rackunit)

  (define s-in (make-channel))
  (define s-out (make-channel))
  (define c-N (string->number
             (string-append
              "#xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
              "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
              "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
              "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
              "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
              "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
              "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
              "fffffffffffff")))
  (define c-g 2)
  (define c-k 3)
  (define creds
    (list (list #"ssquarepants" #"krabbypatties4lyf")
          (list #"splankton" #"ih4rtsharon")
          (list #"mrkrabs" #"mon3ymoneym0ney")))

  (define SRPS
    (new SRPServer%
         [N c-N] [g c-g] [k c-k] [credentials creds]))
  (define SRPC
    (new SRPClient%
         [N c-N] [g c-g] [k c-k] [in s-out] [out s-in]))
  (send SRPS start-listening s-in s-out)
  (check-true (send SRPC
                    authenticate-user
                    #"ssquarepants"
                    #"krabbypatties4lyf"))
  (check-true (send SRPC
                    authenticate-user
                    #"splankton"
                    #"ih4rtsharon"))
  (check-true (send SRPC
                    authenticate-user
                    #"mrkrabs"
                    #"mon3ymoneym0ney"))
  (check-false (send SRPC
                    authenticate-user
                    #"mrkrabs"
                    #"mon3ymoney"))
  (check-false (send SRPC
                    authenticate-user
                    #"splankton"
                    #"killkrabs"))
  (check-false (send SRPC
                    authenticate-user
                    #"ssquarepants"
                    #"imready"))
  (check-false (send SRPC
                    authenticate-user
                    #"pstar"
                    #"duhhh")))
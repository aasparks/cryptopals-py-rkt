#lang racket

; Challenge 36
;; Implement Secure Remote Password (SRP)
(require sha
         racket/random
         math
         "../util/conversions.rkt")
(provide SRPServer%
         SRPClient%)

#|
   To understand SRP, look at how you generate an AES
   key from DH; now, just observe you can do the
   "opposite" operation and generate a numeric
   parameter from a hash. Then:
   Replace A and B with C and S (client and server)

   C&S
     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

   S
     1. Generate salt as a random integer
     2. Generate string xH=SHA256(salt || password)
     3. Convert xH to integer x somehow (put 0x on hexdigest)
     4. Generate v= g**x % N
     5. Save everything but x, xH

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
(define SRPServer%
  (class object%
    (init prime email password)
    (super-new)

    ; private fields
    (define N prime)
    (define G 2)
    (define k 3)
    (define I email)
    (define salt (crypto-random-bytes 8))
    (define V
      (modular-expt G
                    (bytes->integer
                     (sha256
                      (bytes-append salt password)))
                    N))

    ; authenticate : bytes? integer? channel? channel?
    (define/public (authenticate email A in out)
      (thread
       (λ () (auth email A in out))))

    (define/private (auth email A in out)
      ; Send salt, B
      (define b (bytes->integer (crypto-random-bytes 8)))
      (define B (+ (* k V) (modular-expt G b N)))
      (channel-put out (list salt B))
      ; Compute uH
      (define uH (sha256
                  (bytes-append
                   (integer->bytes A)
                   (integer->bytes B))))
      (define u (bytes->integer uH))
      ; Generate S
      (define S (modular-expt (* A (modular-expt V u N))
                              b N))
      (define K (sha256 (integer->bytes S)))
      (define hmac (hmac-sha256 salt K))
      ; C->S hmac
      (define client-hmac (channel-get in))
      ; Check validity
      (channel-put out (bytes=? client-hmac hmac)))))

(define SRPClient%
  (class object%
    (init prime server)
    (super-new)

    (define N prime)
    (define G 2)
    (define k 3)
    (define current-server server)

    ; login : bytes? bytes? -> boolean?
    ;; attempts to login to the SRPServer and returns
    ;; true if the attempt was successful
    (define/public (login email password)
      (define a (bytes->integer (crypto-random-bytes 8)))
      (define A (modular-expt G a N))
      (define out (make-channel))
      (define in (make-channel))
      ; Send I,A
      (send current-server
            authenticate
            email A out in)
      (define-values (salt B) (apply values (channel-get in)))
      ; Compute uH
      (define uH (sha256
                  (bytes-append
                   (integer->bytes A)
                   (integer->bytes B))))
      (define u (bytes->integer uH))
      ; Generate xH, K, S
      (define xH (sha256 (bytes-append salt password)))
      (define x (bytes->integer xH))
      (define S (modular-expt
                 (- B (* k (modular-expt G x N)))
                 (+ a (* u x))
                 N))
      (define K (sha256 (integer->bytes S)))
      (define hmac (hmac-sha256 salt K))
      (channel-put out hmac)
      (channel-get in))))

(module+ test
  (require rackunit
           "../util/test.rkt")

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
  (define e #"ssquarepants@krustyk.com")
  (define pass #"imready")
  (define srp-server (new SRPServer%
                      [prime p]
                      [email e]
                      [password pass]))
  (define client (new SRPClient%
                      [prime p]
                      [server srp-server]))

  (define test-challenge-36
    (test-suite
     "Test 1"
     (check-true (send client login e pass))
     (check-false (send client login e #"blah"))))

  (time-test test-challenge-36))
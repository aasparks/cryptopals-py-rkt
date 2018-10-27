#lang racket

; Challenge 38
;; Offline Dictionary Attack on Simplified SRP
(require racket/random
         math
         sha
         "../util/conversions.rkt")
(provide SimplifiedSRPServer%
         SimplifiedSRPClient%
         MITMSimplifiedSRPServer%)
#|
   S
      x = SHA256(salt || password)
      v = g**x % n
   C->S
      I,A = g**a % n
   S->C
      salt, B = = g**b % n, u = 128 bit random number
   C
      x = SHA256(salt || password)
      S = B**(a+ux) % n
      K = SHA256(S)
   S
      S = (A*v**u)**b % n
      K = SHA256(S)
   C->S
      Send HMAC-SHA256(K,salt)
   S->C
      Send "OK" if HMAC-SHA256(K, salt) validates

   Note that in this protocol, the server's "B" parameter
   doesn't depend on the password (it's just a Diffie-Hellman
   public key)

   Make sure the protocol works given a valid password.

   Now, run the protocol as a MITM attacker, pose as the
   server and use arbitrary values for b, B, u, and salt.

   Crack the password from A's HMAC-SHA256(K, salt)
|#
(define SimplifiedSRPServer%
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
      ; Send salt, B, u
      (define b (bytes->integer (crypto-random-bytes 8)))
      (define B (modular-expt G b N))
      (define u (bytes->integer (crypto-random-bytes 16)))
      (channel-put out (list salt B u))
      ; Generate S
      (define S (modular-expt (* A (modular-expt V u N))
                              b N))
      (define K (sha256 (integer->bytes S)))
      (define hmac (hmac-sha256 salt K))
      ; C->S hmac
      (define client-hmac (channel-get in))
      ; Check validity
      (channel-put out (bytes=? client-hmac hmac)))))

(define SimplifiedSRPClient%
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
      ; C->S I,A
      (define-values (salt B u) (apply values (channel-get in)))
      (define x (bytes->integer (sha256 (bytes-append salt password))))
      (define S (modular-expt B (+ a (* u x)) N))
      (define K (sha256 (integer->bytes S)))
      (define hmac (hmac-sha256 salt K))
      (channel-put out hmac)
      (channel-get in))))

(define MITMSimplifiedSRPServer%
  (class object%
    (init prime)
    (super-new)

    (init-field [password #""])
    (define G 2)
    (define k 3)
    (define N prime)

    (define/public (get-password)
      password)

    (define/public (authenticate email A in out)
      (thread
       (λ () (auth email A in out))))

    (define/private (auth email A in out)
      (define salt (make-bytes 8 0))
      (define b 1)
      (define B 2)
      (define u 1)
      (channel-put out (list salt B u))
      (define client-hmac (channel-get in))
      (dictionary-attack client-hmac salt A u)
      (channel-put out #false))

    (define/private (dictionary-attack client-hmac salt A u)
      ;; not using a real dictionary
      (define dictionary
        (list #"password" #"password1"
              #"ready" #"krustykrab"
              #"invalid" #"imready"
              #"1234567890"))
      (for ([i (in-range (length dictionary))])
        (define pass (list-ref dictionary i))
        (define xH (sha256 (bytes-append salt pass)))
        (define x (bytes->integer xH))
        (define v (modular-expt G x N))
        (define S (modulo (* A v) N))
        (define K (sha256 (integer->bytes S)))
        (define hmac (hmac-sha256 salt K))
        #:final (bytes=? hmac client-hmac)
        (when (bytes=? hmac client-hmac)
          (set! password pass))))))

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
  (define srp-server (new SimplifiedSRPServer%
                      [prime p]
                      [email e]
                      [password pass]))
  (define client (new SimplifiedSRPClient%
                      [prime p]
                      [server srp-server]))

  (define test-simple-srp
    (test-suite
     "Test 1"
     (check-true (send client login e pass))
     (check-false (send client login e #"blah"))))

  (define mitm-server (new MITMSimplifiedSRPServer%
                           [prime p]))
  (define mitm-client (new SimplifiedSRPClient%
                           [prime p]
                           [server mitm-server]))

  (define test-mitm
    (test-suite
     "Test MITM"
     (check-false (send mitm-client login e pass))
     (check-equal? (send mitm-server get-password)
                   #"imready")))

  (define test-challenge-38
    (test-suite
     "Challenge 38"
     test-simple-srp
     test-mitm))

  (time-test test-challenge-38))
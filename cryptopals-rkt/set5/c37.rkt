#lang racket

; Challenge 37
;; Break SRP with a Zero Key
(require racket/random
         math
         sha
         "c36.rkt"
         "../util/conversions.rkt")

#|
   Get your SRP working in an actual client-server setting.
   "Log in" with a valid password using the protocol.

   Now log in without your password by having the client send
   0 as its "A" value. What does this do to the "S" value that
   both sides compute?

   Now log in without your password by having the client send
   N, N*2, etc.
|#
(define EvilSRPClient%
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
    (define/public (login email password A)
      (define a (bytes->integer (crypto-random-bytes 8)))
      (define out (make-channel))
      (define in (make-channel))
      ; Send I,A
      (send current-server
            authenticate
            email A out in)
      (define-values (salt B) (apply values (channel-get in)))
      (define K (sha256 (integer->bytes 0)))
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
  (define client (new EvilSRPClient%
                      [prime p]
                      [server srp-server]))

  (define test-challenge-37
    (test-suite
     "Challenge 37"
     (check-true (send client login e pass 0))
     (check-true (send client login e #"blah" 0))
     (check-true (send client login e pass p))
     (check-true (send client login e #"blah" p))
     (check-true (send client login e pass (* p 2)))
     (check-true (send client login e #"blah" (* p 2)))))

  (time-test test-challenge-37))
#lang racket/base

(require racket/random
         racket/list
         "../util/sha1.rkt"
         "../util/conversions.rkt"
         "c28.rkt")
; Challenge 29
;; Break a SHA-1 Keyed MAC Using Length Extension

#|
   Secret-prefix SHA-1 MACs are trivially breakable.

   The attack on secret-prefix SHA-1 relies on the fact that you
   can take the output of SHA-1 and use it as a new starting point
   for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it
   more data".

   Since the key precedes the data in secret-prefix, any additional
   data you feed the SHA-1 hash in this fashion will appear to have
   been hashed with the secret key.

   To carry out the attack, you'll need to account for the fact that
   SHA-1 is "padded" with the bit-length of the message; your
   forged message will need to include that padding. We call this
   "glue padding". The final message you actually forge will be:
     SHA1(key || original-message || glue-padding || new-message)

   (where the final padding on the whole constructed message is
   implied)

   Note that to generate the glue padding, you'll need to know the
   original bit length of the message; the message itself is known
   to the attacker, but the secret key isn't, so you'll need to guess
   at it.

   This sounds more complicated than it is in practice.

   To implement the attack, first write the function that computes
   the MD padding of an arbitrary message and verify that you're
   generating the same padding that your SHA-1 implementation is using.
   This should take you 5-10 minutes.

   Now take the SHA-1 secret-prefix MAC of the message you want to
   forge --- this is just a SHA-1 hash --- and break it into 32-bit
   SHA-1 registers.

   Modify your SHA-1 implementation so that callers can pass in new
   values for the registers (they normally start at magic numbers).
   Whith the registers 'fixated', hash the additional data you want
   to forge.
     Note: this will be changed in "../../sha1/sha1.rkt"

   Using this attack, generate a secret-prefix MAC under a secret
   key (choose a random word) of the string
    "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

   Forge a variant of this message that ends with ";admin=true"
|#

; this is known
(define MESG #"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
(define SUFF #";admin=true")

; glue-padding
;; This works exactly like pre-process from my SHA-1 implementation.
;; Since I wrote it, I don't feel bad about copying it and modifying
;; it to work here.
(define (glue-padding message)
  (define msg-len (bytes-length message))
  (define msg-bit-len (* 8 msg-len))
  ; pad the message
  (define new-len
    (*
     64 ; block size
     (ceiling (/ (+ msg-len 9) 64)))) ; num blocks
  (define new-msg (make-bytes new-len 0)) ; create buffer
  ; fill buffer with msg + the 1 bit
  (bytes-copy! new-msg 0 (bytes-append
                          message
                          (make-bytes 1 #x80)))
  ; append the length to the end
  (define msg-tail (integer->integer-bytes msg-bit-len 8 #f #t))
  (bytes-copy! new-msg
               (- new-len (bytes-length msg-tail))
               msg-tail)
  ; return the new message
  new-msg)

; forge-registers : bytes -> vector
;; convert the given message to SHA-1 registers vector
(define (forge-registers message)
  (list->vector
   (map
    (λ (num)
      (integer-bytes->integer num #f #t))
        (map list->bytes
             (split-list
              (bytes->list
               (sha1-mac message)))))))

; split-list : (listof bytes) integer -> (listof (listof bytes))
;; takes a list and splits into a list of lists of size n
(define (split-list lst (n 4))
  (cond
    [(empty? lst) empty]
    [else (cons (take lst n)
                (split-list (drop lst n) n))]))

; forge-mac : bytes bytes -> bytes
;; creates a valid mac for message || inject
(define (forge-mac message inject)
  (define forged-message (forge-message message inject))
  (sha-1 inject 
         (forge-registers message)
         (+ 16 (bytes-length forged-message))))

; forge-message : bytes bytes -> bytes
;; creates the forged message to send in
(define (forge-message message inject)
  (bytes-append
   (subbytes
    (glue-padding
     (bytes-append (make-bytes 16 0)
                   message))
    16)
   inject))

(module+ test
  (require rackunit)

  (check-equal?
   (split-list (bytes->list #"DEADBEEF") 4)
   (list (bytes->list #"DEAD")
         (bytes->list #"BEEF")))

  (check-equal? (ascii->hex (forge-mac MESG SUFF))
                (ascii->hex (sha1-mac (forge-message MESG SUFF)))))

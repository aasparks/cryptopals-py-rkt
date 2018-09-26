#lang racket

; Challenge 30
;; Break an MD4 Keyed MAC Using Length Extension
(require "../md4/md4.rkt"
         racket/random)

#|
   Second verse, same as the first, but use MD4
   instead of SHA-1. Having done this attack once
   against SHA-1, the MD4 variant should take much
   less time; mostly just the time you'll spend
   Googling for an implementation of MD4.
|#

; Since I've been doing it this way so far, I'm
; just going to implement MD4 myself. It's a
; lot like SHA-1.

; Let's define the mac function and pretend
; we don't have access to the key

(define KEY (crypto-random-bytes 16))

; mac : bytes? -> bytes?
;; creates the mac from the message using a random key
(define (mac msg)
  (md4 (bytes-append KEY msg)))

; Now for the attack stuff
(define MESG #"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
(define SUFF #";admin=true")

; glue-padding
;; This works exactly like pre-process.
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
  (define msg-tail (integer->integer-bytes msg-bit-len 8 #f #f))
  (bytes-copy! new-msg
               (- new-len (bytes-length msg-tail))
               msg-tail)
  
  ; return the new message
  new-msg)

; forges registers the same. only
; difference is that md4 is little-endian
(define (forge-registers message)
  (list->vector
   (map
    (λ (num)
      (integer-bytes->integer num #f #f))
        (map list->bytes
             (split-list
              (bytes->list
               (mac message)))))))

; split-list
;; takes a list and splits into a list of lists of size n
(define (split-list lst (n 4))
  (cond
    [(empty? lst) empty]
    [else (cons (take lst n)
                (split-list (drop lst n) n))]))

; forges hmac just like with sha-1
(define (forge-mac message inject)
  (define forged-message (forge-message message inject))
  (md4 inject 
         (forge-registers message)
         (+ 16 (bytes-length forged-message))))

; forge-message
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
  (require rackunit
           "../set1/c1.rkt")

  (check-equal?
   (split-list (bytes->list #"DEADBEEF") 4)
   (list (bytes->list #"DEAD")
         (bytes->list #"BEEF")))

  (check-equal? (ascii->hex (forge-mac MESG SUFF))
                (ascii->hex (mac (forge-message MESG SUFF)))))

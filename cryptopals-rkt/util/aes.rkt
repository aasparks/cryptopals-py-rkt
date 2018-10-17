#lang racket/base

#|
  This is my implementation of AES-128 for Racket. The only way I can find
  to get AES as of now is through messy ffi's. This was just a fun exercise for
  me. It's not meant to be secure or even that fast. In fact, it was made to be
  broken, for the Cryptopals challenges. It currently supports ECB, CBC, and CTR
  modes.
|#
(require racket/stream
         racket/sequence
         racket/list
         racket/match
         racket/vector
         "aes/tables.rkt")

(provide aes-128-encrypt
         aes-128-decrypt)


;; number of columns for the state
(define Nb 4)
;; number of 32-bit words comprising the key
(define Nk 4)
;; length of the key in bytes
(define KeyLen 16)
;; number of rounds
(define Nr 10)
  

;;;; Cipher
;; byte state[4 Nb]
;; state = in
;; AddRoundKey(state  w[0  Nb-1])
;; for round = 1 step 1 to Nr-1
;;   SubBytes(state)
;;   ShiftRows(state)
;;   MixColumns(state)
;;   AddRoundKey(state  w[round*Nb]  (round+1)*Nb-1)
;; end for
;; SubBytes(state)
;; ShiftRows(state)
;; AddRoundKey(state  w[Nr*Nb  (Nr+1)*Nb-1])
;; out = state
(define (Cipher w in)
  (define state
    (foldl (λ (i s)
             (AddRoundKey
              (MixColumns
               (ShiftRows
                (SubBytes s)))
              (get-RoundKey w i)))
           (AddRoundKey in (get-RoundKey w 0))
           (stream->list (in-range 1 Nr))))
  ; don't mix columns on first or last
  (AddRoundKey
   (ShiftRows
    (SubBytes state))
   (get-RoundKey w Nr)))

;;;; InvCipher
;; AddRoundKey(state w[Nr*Nb, (Nr+1)*Nb - 1])
;; for round = Nr-1 step -1 downto 1
;;   InvShiftRows(state)
;;   InvSubBytes(state)
;;   AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
;;   InvMixColumns(state)
;; endfor
;; InvShiftRows(state)
;; InvSubBytes(state)
;; AddRoundKey(state, w[0, Nb-1])
(define (InvCipher w in)
  (define state
    (foldl (λ (i s)
             (InvMixColumns
              (AddRoundKey
               (InvSubBytes
                (InvShiftRows s))
               (get-RoundKey w i))))
           (AddRoundKey in (get-RoundKey w Nr))
           (sequence->list (in-range (sub1 Nr) 0 -1))))
  (AddRoundKey
   (InvSubBytes
    (InvShiftRows state))
   (get-RoundKey w 0)))

;; turns given ciphertxt into an input vector
(define (text->input-vector txt)
  (unless (= (bytes-length txt) 16)
    (error 'aes-128 "input is not of length 16: ~v" (string-length txt)))
  (for/vector ([i (in-range 4)])
    (for/vector ([j (in-range 4)])
      (bytes-ref txt (+ i (* j 4))))))

;; turns an input vector into a byte string
(define (input-vector->text vec)
  (list->bytes
   (flatten
    (for/list ([i (in-range 4)])
      (for/list ([j (in-range 4)])
        (state-at vec j i))))))

;; Creates the Round Key matrix for round i
(define (get-RoundKey w i)
  (for/vector ([j (in-range 4)])
    (for/vector ([k (in-range 4)])
      (bitwise-and
       #xFF
       (arithmetic-shift
        (vector-ref w (+ k (* i 4)))
        (- (* (add1 j) 8) 32))))))


;;;; AddRoundKey
;; A Round Key is added to the State by a simple
;; bitwise XOR operation. Each Round Key consists
;; of Nb words from the key schedule
(define (AddRoundKey state w)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (in-range 4)])
      (bitwise-xor (state-at state i j)
                   (state-at w i j)))))


;;;; ShiftRows
;; The bytes in the last three rows of the State are
;; cyclically shifted over different numbers of bytes
(define (ShiftRows state)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (ring-list i)])
      (state-at state i j))))

;;;; InvShiftRows
(define (InvShiftRows state)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (inv-ring-list i)])
      (state-at state i j))))

;; Generates a list for iterating like a ring
(define (ring-list i)
  (match i
    [0 '(0 1 2 3)]
    [1 '(1 2 3 0)]
    [2 '(2 3 0 1)]
    [3 '(3 0 1 2)]))
(define (inv-ring-list i)
  (match i
    [0 '(0 1 2 3)]
    [1 '(3 0 1 2)]
    [2 '(2 3 0 1)]
    [3 '(1 2 3 0)]))

;; Useful debug to print matrix in hex
(define (print-matrix mat)
  (for ([i (in-range (vector-length mat))])
    (printf "~x ~x ~x ~x\n"
            (state-at mat i 0)
            (state-at mat i 1)
            (state-at mat i 2)
            (state-at mat i 3))))

;; flips the rows and columns of a vector of vectors
(define (flip-rows-columns vec)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (in-range 4)])
      (state-at vec j i))))

;;;; MixColumns
;; Operates on the State column-by-column  treating each
;; column as a four-term polynomial. The columns are considered
;; as polynomials over GF(2^8) and multiplied modulo x^4+1 with a
;; fixed polynomial a(x).
(define (MixColumns state)
  (flip-rows-columns
   (for/vector ([i (in-range 4)])
     (for/vector ([j (in-range 4)])
       (mixer i j state)))))

;; helper function for the MixColumns operation
(define (mixer i j state)
  (define lst (mix-idxes j))
  (bitwise-xor (XTIME (state-at state (first lst) i))
               (state-at state (second lst) i)
               (state-at state (third lst) i)
               (XTIME (state-at state (fourth lst) i))
               (state-at state (fifth lst) i)))

;; sort of a lame way of getting the proper values from  the state
(define (mix-idxes j)
  (match j
    [0 '(0 3 2 1 1)]
    [1 '(1 0 3 2 2)]
    [2 '(2 1 0 3 3)]
    [3 '(3 2 1 0 0)]))
;; also lame
(define (inv-mix-masks i)
  (match i
    [0 '(#x0e #x0b #x0d #x09)]
    [1 '(#x09 #x0e #x0b #x0d)]
    [2 '(#x0d #x09 #x0e #x0b)]
    [3 '(#x0b #x0d #x09 #x0e)]))

;;;; InvMixColumns
(define (InvMixColumns state)
  (flip-rows-columns
   (for/vector ([i (in-range 4)])
     (inv-mixer i state))))

(define (inv-mixer i state)
  (for/vector ([k (in-range 4)])
    (define lst (inv-mix-masks k))
    (bitwise-xor (MULTIPLY (state-at state 0 i) (first lst))
                 (MULTIPLY (state-at state 1 i) (second lst))
                 (MULTIPLY (state-at state 2 i) (third lst))
                 (MULTIPLY (state-at state 3 i) (fourth lst)))))

;; XTIME macro. obviously not a macro b/c we don't do that in this house
(define (XTIME num)
  (bitwise-and
   #xFF
   (bitwise-xor
    (arithmetic-shift num 1)
    (if (= (arithmetic-shift num -7) 1)
        #x01b
        0))))

;; MULTIPLY macro
(define (MULTIPLY x y)
  (bitwise-xor
   (* x (bitwise-and y 1))
   (* (XTIME x) (bitwise-and (arithmetic-shift y -1) 1))
   (* (XTIME (XTIME x)) (bitwise-and (arithmetic-shift y -2) 1))
   (* (XTIME (XTIME (XTIME x))) (bitwise-and (arithmetic-shift y -3) 1))
   (* (XTIME (XTIME (XTIME (XTIME x)))) (bitwise-and (arithmetic-shift y -4) 1))))

;; shorthand for getting values from state
(define (state-at state i j)
  (vector-ref (vector-ref state i) j))

;;;; SubBytes
;; SubBytes() is a non-linear byte substitution that
;; operates independently on each byte of the State
;; using a substitution table (S-box). 
(define (SubBytes state)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (in-range 4)])
      (vector-ref Sbox
                  (state-at state i j)))))

;;;; InvSubBytes
(define (InvSubBytes state)
  (for/vector ([i (in-range 4)])
    (for/vector ([j (in-range 4)])
      (vector-ref invSbox
                  (state-at state i j)))))


;;;; Word
;; takes in 4 byte values an combines them
;; into one 32-bit value
(define (Word blist)
  (integer-bytes->integer
   (list->bytes blist)
   #false #true))

;;;; Key Expansion
;;; byte key[4*Nk]  word w[Nb*(Nr+1)]  Nk
;; word temp
;; i = 0
;; while i < Nk
;;   w[i] = word(key[4*i]  key[4*i+1]  key[4*i+2]  key[4*i+3])
;;   i += 1
;; end while
;; i = Nk
;; while (i < Nb * (Nr+1))
;;   temp = w[i-1]
;;   if (i mod Nk == 0)
;;     temp = SubWord(RotWord(temp)) XOR Rcon[i/Nk]
;;   else if (Nk > 6 and i mod Nk = 4)
;;     temp = SubWord(temp)
;;   end if
;;   w[i] = w[i-Nk] XOR temp
;;   i += 1
;; endwhile

;; expands according to pseudocode above
(define (key-expansion key)
  (foldl
   (λ (i w)
     (define temp (vector->values (vector-take-right w 1)))
     (define t (cond
                 [(= (modulo i Nk) 0) (bitwise-xor (SubWord (RotWord temp))
                                                   (vector-ref Rcon (sub1 (/ i Nk))))]
                 [(and (> Nk 6) (= (modulo i Nk) 4)) (SubWord temp)]
                 [else temp]))
     (vector-append
      w
      (vector
       (bitwise-xor t
                    (vector-ref w (- i Nk))))))
   (build-vector Nk (λ (i) (key-pieces key i))) ; first loop
   (sequence->list (in-range Nk (* Nb (add1 Nr))))))

;; get key[4*i] ... key[4*i+3]
(define (key-pieces key i)
  (integer-bytes->integer
   (get-4bytes key i)
   #f #t))

;;;; Subword
;; Takes a four-byte input word and applies
;; the S-box to each of the four bytes to produce
;; an output word
(define (SubWord num)
  (Word (build-list 4 (λ (i) (get-sbox-value (get-byte num i))))))

;; Extract 4bytes from a [num-bits]-bit key
(define (get-4bytes num i)
  (subbytes num (* i 4) (* (add1 i) 4)))

;; Extract a byte from a 32-bit integer
(define (get-byte num i)
  (bitwise-and
   #xFF
   (arithmetic-shift
    num
    (- (- 32 (* 8 (add1 i)))))))

;; xor two byte strings together because that's the way it should be
(define (xor-bstrs bstr1 bstr2)
  (list->bytes
   (map bitwise-xor
        (bytes->list bstr1)
        (bytes->list bstr2))))

;; Gets the value sbox[i]
(define (get-sbox-value i)
  (vector-ref Sbox i))

;;;; RotWord
(define (RotWord num)
  (define blist (build-list 4 (λ (e) (get-byte num e))))
  (Word (list (second blist)
              (third blist)
              (fourth blist)
              (first blist))))

;; gets a block from a byte string
(define (get-block txt i [blocksize 16])
  (subbytes txt (* blocksize i) (* blocksize (add1 i))))

; Performs error checking on length
(define (error-check txt)
  (unless (= 16 (bytes-length txt))
    (error 'aes "input is not 16 bytes ~v\n" (bytes-length txt))))

;; Actual encryption of a single block
;; Takes in two byte strings as the plaintext and key
(define (aes-128-encrypt/block txt key)
  (map error-check (list txt key))
  (input-vector->text
   (Cipher (key-expansion key)
           (text->input-vector txt))))

;; Decryption of a single block
;; Takes in two byte strings as the ciphertext and key
(define (aes-128-decrypt/block txt key)
  (map error-check (list txt key))
  (input-vector->text
   (InvCipher (key-expansion key)
              (text->input-vector txt))))

;; ECB mode for AES
; encrypt
(define (aes-128-ecb-encrypt txt key)
  (apply bytes-append
   (for/list ([i (in-range (/ (bytes-length txt) 16))])
     (aes-128-encrypt/block (get-block txt i) key))))
; decrypt
(define (aes-128-ecb-decrypt txt key)
  (apply bytes-append
   (for/list ([i (in-range (/ (bytes-length txt) 16))])
     (aes-128-decrypt/block (get-block txt i) key))))

;; CBC mode for AES
; encrypt
(define (aes-128-cbc-encrypt txt key iv)
  (map error-check (list key iv))  
  (define last-block (box iv))
  (apply bytes-append
   (for/list ([i (in-range (/ (bytes-length txt) 16))])
     (define cur-block (get-block txt i))
     (define enc
       (aes-128-encrypt/block (xor-bstrs cur-block (unbox last-block))
                        key))
     (set-box! last-block enc)
     enc)))
; decrypt
(define (aes-128-cbc-decrypt txt key iv)
  (map error-check (list key iv))
  (define last-block (box iv))
  (apply bytes-append
         (for/list ([i (in-range (/ (bytes-length txt) 16))])
           (define cur-block (get-block txt i))
           (define dec (aes-128-decrypt/block cur-block key))
           (define pt (xor-bstrs dec (unbox last-block)))
           (set-box! last-block cur-block)
           pt)))

;; CTR mode for AES
(define (aes-128-ctr txt key nonce)
  (xor-bstrs
   (build-keystream txt key nonce)
   txt))

; build the keystream for CTR mode
(define (build-keystream txt key nonce)
  (define num-blocks
    (ceiling (/ (bytes-length txt) 16)))
  (subbytes
   (apply bytes-append
    (map (λ (i)
           (aes-128-encrypt/block
            (bytes-append (little-endian nonce)
                          (little-endian i))
            key))
         (build-list num-blocks values)))
   0
   (bytes-length txt)))

;; convert a number to a bytestring in little-endian
;; in python this is just struct.pack('<Q', num)
(define (little-endian num)
  (integer->integer-bytes
   num 8 #f #f))

;; top-level AES-128 define
;; accepts an encryption mode (ECB by default) and runs the right function
;; from there.
;; iv can be iv or nonce. there is no default iv for CBC mode. sorry.
(define (aes-128-encrypt txt key [iv 0] #:mode [md 'ECB])
  (match md
    [(or 'ECB 'ecb) (aes-128-ecb-encrypt txt key)]
    [(or 'CBC 'cbc) (if (equal? iv 0)
              (aes-128-cbc-encrypt txt key (make-bytes 16 0))
              (aes-128-cbc-encrypt txt key iv))]
    [(or 'CTR 'ctr) (aes-128-ctr txt key iv)]
    [else (error 'aes-128-encrypt
                 "unknown mode ~v. valid modes are 'ECB 'CBC and 'CTR"
                 md)]))
;; top-level AES-128 define
;; same as encrypt. accepts a mod and runs the right function.
(define (aes-128-decrypt txt key [iv 0] #:mode [md 'ECB])
  (match md
    [(or 'ecb 'ECB) (aes-128-ecb-decrypt txt key)]
    [(or 'cbc 'CBC )(if (equal? iv 0)
              (aes-128-cbc-decrypt txt key (make-bytes 16 0))
              (aes-128-cbc-decrypt txt key iv))]
    [(or 'ctr 'CTR) (aes-128-ctr txt key iv)]
    [else (error 'aes-128-decrypt
                 "unknown mode ~v. valid modes are 'ECB 'CBC and 'CTR"
                 md)]))

(module+ test
  (require rackunit
           rackunit/text-ui
           "test.rkt"
           "../set1/c1.rkt")

  ; I wouldn't recommend reading through this. It got messy.

  (define test-get-byte
    (test-suite
     "Get byte"
     (check-equal? (get-byte 65 3)
                   65)
     (check-equal? (get-byte 1701209960 0)
                   #x65)
     (check-equal? (get-byte 1701209960 1)
                   #x66)
     (check-equal? (get-byte 1701209960 2)
                   #x67)
     (check-equal? (get-byte 1701209960 3)
                   #x68)))

  (define test-words
    (test-suite
     "Word functions"
     (check-equal? (Word (list 1 2 3 4))
                   #x01020304)
     (check-equal? (SubWord #x01020304)
                   #x7c777bf2)
     (check-equal? (RotWord #x01020304)
                   #x02030401)
     (check-equal? (XTIME #x57)
                   #xae)
     (check-equal? (XTIME #xae)
                   #x47)
     (check-equal? (arithmetic-shift #x47 1)
                   #x8e)
     (check-equal? (XTIME #x47)
                   #x8e)
     (check-equal? (XTIME #x8e)
                   #x07)))
  
  (define bkey #"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c")
  (define binput #"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34")
  (define binputv (vector (vector #x32 #x88 #x31 #xe0)
                          (vector #x43 #x5a #x31 #x37)
                          (vector #xf6 #x30 #x98 #x07)
                          (vector #xa8 #x8d #xa2 #x34)))
  (define bw (vector-immutable #x2b7e1516 #x28aed2a6 #xabf71588 #x09cf4f3c #xa0fafe17
                               #x88542cb1 #x23a33939 #x2a6c7605 #xf2c295f2 #x7a96b943
                               #x5935807a #x7359f67f #x3d80477d #x4716fe3e #x1e237e44
                               #x6d7a883b #xef44a541 #xa8525b7f #xb671253b #xdb0bad00
                               #xd4d1c6f8 #x7c839d87 #xcaf2b8bc #x11f915bc #x6d88a37a
                               #x110b3efd #xdbf98641 #xca0093fd #x4e54f70e #x5f5fc9f3
                               #x84a64fb2 #x4ea6dc4f #xead27321 #xb58dbad2 #x312bf560
                               #x7f8d292f #xac7766f3 #x19fadc21 #x28d12941 #x575c006e
                               #xd014f9a8 #xc9ee2589 #xe13f0cc8 #xb6630ca6))

  (define test-cipher-funcs
    (test-suite
     "Cipher functions"
     (check-equal? (text->input-vector binput)
                   binputv)
     (check-equal? (get-RoundKey bw 0)
                   (vector (vector #x2b #x28 #xab #x09)
                           (vector #x7e #xae #xf7 #xcf)
                           (vector #x15 #xd2 #x15 #x4f)
                           (vector #x16 #xa6 #x88 #x3c)))
     (check-equal? (key-expansion bkey)
                   bw)
     (check-equal? (input-vector->text binputv)
                   binput)
     (check-equal? (InvSubBytes (SubBytes binputv))
                   binputv)
     (check-equal? (InvShiftRows (ShiftRows binputv))
                   binputv)
     (check-equal? (InvMixColumns (MixColumns binputv))
                   binputv)
     (check-equal? (Cipher (key-expansion bkey)
                           binputv)
                   (vector (vector #x39 #x02 #xdc #x19)
                           (vector #x25 #xdc #x11 #x6a)
                           (vector #x84 #x09 #x85 #x0b)
                           (vector #x1d #xfb #x97 #x32)))
     (check-equal? (InvCipher (key-expansion bkey)
                              (vector (vector #x39 #x02 #xdc #x19)
                                      (vector #x25 #xdc #x11 #x6a)
                                      (vector #x84 #x09 #x85 #x0b)
                                      (vector #x1d #xfb #x97 #x32)))
                   binputv)
     (check-equal? (aes-128-encrypt/block binput bkey)
                   #"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32")))

  ; Test 1
  (define test1input #"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")
  (define test1key #"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
  (define test1output #"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a")
   
  (define test-vector-1
    (test-suite
     "Test vector 1"
     (check-equal? (aes-128-encrypt/block test1input test1key)
                   test1output)
     (check-equal? (aes-128-decrypt/block test1output test1key)
                   test1input)
     (check-equal? (aes-128-decrypt/block (aes-128-encrypt/block test1input test1key)
                                          test1key)
                   test1input)
     (check-equal? (aes-128-ecb-encrypt (bytes-append test1input test1input)
                                        test1key)
                   (bytes-append test1output test1output))
     (check-equal? (aes-128-ecb-decrypt
                    (aes-128-ecb-encrypt (bytes-append test1input test1input) test1key)
                    test1key)
                   (bytes-append test1input test1input))))
  (define ctr-txt
    (base64->ascii #"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
  (define ctr-key
    #"YELLOW SUBMARINE")
  (define ctr-pt
    #"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
  (define test-mode-option
    (test-suite
     "Modes"
     (check-equal? ; CTR mode
      (aes-128-decrypt ctr-txt ctr-key 0 #:mode 'CTR)
      ctr-pt)
     (check-equal?
      (aes-128-decrypt (aes-128-encrypt ctr-pt ctr-key 0 #:mode 'CTR)
                       ctr-key 0 #:mode 'CTR)
      ctr-pt)
     (check-equal?
      (aes-128-decrypt (aes-128-encrypt (make-bytes 64 65) ctr-key)
                       ctr-key #:mode 'ECB)
      (make-bytes 64 65))
     (check-equal?
      (aes-128-decrypt (aes-128-encrypt (make-bytes 64 65) ctr-key (make-bytes 16 0) #:mode 'CBC)
                       ctr-key (make-bytes 16 0) #:mode 'CBC)
      (make-bytes 64 65))
     (check-exn exn:fail?
                (λ () (aes-128-encrypt (make-bytes 15 0) (make-bytes 16 0) #:mode 'ecb)))
     (check-exn exn:fail?
                (λ () (aes-128-encrypt (make-bytes 16 0) (make-bytes 13 0) #:mode 'ecb)))))
  (define all-tests
    (test-suite
     "All tests"
     test-get-byte
               test-words
               test-cipher-funcs
               test-vector-1
               test-mode-option))

  (time-test all-tests))
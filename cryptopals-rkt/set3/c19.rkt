#lang racket

(require "../aes.rkt")

;;; Take your CTR encrypt/decrypt function and fix its nonce value to 0.
;;; Generate a random AES key.
(define NONCE 0)
(define KEY (crypto-random-bytes 16))

;;; In successive encryptions, encrypt each line of the base64 decodes of the following,
;;; producing multiple independent ciphertexts



;;; Because the CTR nonce wasn't randomized for each encryption, each ciphertext
;;; has been encrypted against the same keystream. This is very bad.

;;; Understanding that, like most stream ciphers, the actual encryption of a byte
;;; of data boils down to a single XOR operation, it should be plain that:
;;;     CT-BYTE ^ PT-BYTE = KEYSTREAM-BYTE
;;; And since the keystream is the same for every ciphertext:
;;;     CT-BYTE ^ KEYSTREAM-BYTE = PT-BYTE

;;; Attack this cryptosystem piecemeal: guess letters, use expected English language
;;; frequence to validate guesses, catch common trigrams, and so on.
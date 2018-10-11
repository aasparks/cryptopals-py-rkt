"""
Challenge 19
Break fixed-nonce CTR mode using substitutions

Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a
random AES key.

In successive encryptions (not in one by running CTR stream), encrypt each line
the base64 decodes of the following, producing multiple independent ciphertexts.

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has
been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any
block cipher run in CTR mode), the actual "encryption" of a byte of data boils
down to a single XOR operation, it should be plain that:
     CTXT-BYTE ^ PTXT-BYTE = KEY-BYTE
And since the keystream is the same for every ciphertext:
     CTXT-BYTE ^ KEY-BYTE = PTXT-BYTE

Attack this cryptosystem piecemeal; guess letters, use expected English language
frequency to validate guesses, catch common English trigrams, and so on.

Points for automating this, but part of the reason I'm having you do this is
that I think this approach is suboptimal.

"""
import c18
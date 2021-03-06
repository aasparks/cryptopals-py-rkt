"""
**Challenge 20**

*Break Fixed-Nonce CTR Statistically*

In this file find a similar set of base64'd plaintext. Do with them exactly what
you did with the first, but solve the problem differently.

Instead of making spot guesses as to known plaintext, treat the collection of
ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a
fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a
common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating-key XOR,
with a key size of the length of the ciphertext you XOR'd.
"""

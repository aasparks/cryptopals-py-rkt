"""
Challenge 17
The CBC Padding Oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

    MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
    MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
    MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
    MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
    MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
    MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
    MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
    MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
    MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
    MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

...generate a random AES key (which it should save for all future encryptions),
pad the string out to the 16-byte AES block size and CBC-encrypt it under that
key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function,
decrypt it, check its padding, and return true or false depending on whether the
padding is valid.

It turns out that it's possible to decrypt the ciphertexts provided by the first
function.

The decryption here depends on a side-channel leak by the decryption function.
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it.
What I'll say is this:

The fundamental insight behind this attack is that the byte \x01 is valid
padding, and occurs in 1/256 trials of "randomized" plaintexts produced by
decrypting a tampered ciphertext.

\x02 in isolation is not valid padding.

\x02\x02 is valid padding, but is much less likely to occur randomly than \x01.

\x03\x03\x03 is even less likely.

So you can assume that if you corrup a decryption AND it had valid padding, you
know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded".
Padding oracles have nothing to do with the actual padding on a CBC plaintext.
It's an attack that targets a specific bit of code that handles decryption. You
can mount a padding oracle on any CBC block, whether it's padded or not.
"""

import sys, os, random, unittest
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
import c10, c9, c6, c2, c1

DEBUG = False;
key   = os.urandom(16)
iv    = os.urandom(16)
strs  = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
         b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
         b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
         b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
         b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
         b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
         b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
         b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
         b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
         b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

# The encryption oracle. Picks a random string
# and encrypts it.
def encryption_oracle():
    """
    Encrypts a random string under AES-128-CBC

    Returns:
        A random, encrypted bytestring
    """
    pt = random.choice(strs)
    pt = c1.base64toascii(pt)
    pt = c9.pkcs7_pad(pt)
    return c10.aes_128_cbc_encrypt(pt, key, iv)

# The decryption oracle. Really the padding oracle.
# Decrypts and determines if the padding is valid.
def decryption_oracle(txt):
    """
    Decrypts the given ciphertext and determines if the padding is valid
    for it.

    Args:
        txt: The encrypted ciphertext

    Returns:
        True if the padding is valid.
    """
    ct = c10.aes_128_cbc_decrypt(txt, key, iv)
    try:
        if DEBUG:
            print('Pad byte: ' + str(ct[-1]))
        ct = c9.pkcs7_unpad(ct)
        return True
    except:
        return False

# The actual attack. Implemented top-down, we can
# ignore the real magic. This just iterates through
# the blocks backwards.
def cbc_padding_attack():
    """
    Performs the CBC padding attack on the encryption oracle.

    Returns:
        The decrypted secret string.
    """
    # The IV is given so we can get all blocks
    txt        = iv + encryption_oracle()
    num_blocks = len(txt) // 16
    result     = b''
    for i in reversed(range(1, num_blocks)):
        result = attack_block(txt, i) + result
    return c9.pkcs7_unpad(result)

# Basically the same thing as the last problem, it just
# iterates through each byte backwards.
def attack_block(txt, block_num):
    """
    Attacks a single block of the ciphertext.

    Args:
        txt: The full ciphertext
        block_num: The block number to attack

    Returns:
        The plaintext of this block.
    """
    plaintext  = b''
    block      = c6.get_block(txt, block_num)
    prev_b     = c6.get_block(txt, block_num - 1)
    for i in reversed(range(16)):
        p = attack_byte(block, prev_b, i, plaintext)
        plaintext = p + plaintext
    return plaintext

# This is where the magic happens.
def attack_byte(block, prev_block, byte_num, plaintext):
    """
    Attacks a single byte using the padding oracle attack. This function
    contains the real magic for the attack.

    Args:
        block: The block of ciphertext that is being attacked.
        prev_block: The previous block of ciphertext used to attack the current one.
        byte_num: The byte number of the block that we are getting.
        plaintext: The known plaintext so far.

    Returns:
        The byte of decoded byte of plaintext

    Raises:
        RuntimeException if no byte can be found
    """
    # Knownxor is super tricky. Read the link from the readme.
    # We want all the last values to be good padding.
    # To do this we xor the prev_block with the known plaintext with
    # the value we want to get for padding.
    knownxor = b''
    if (len(plaintext) > 0):
        knownxor = c2.xorstrs(prev_block[-len(plaintext):], plaintext)
        knownxor = c2.xorstrs(bytes([16-byte_num] * len(plaintext)), knownxor)
    # Test each byte, returning when the padding is valid.
    for i in range(1, 256):
        bad_prev_b = bytes([0]) * byte_num
        # The magic here will only allow for valid padding when i is
        # the same as the value of the original plaintext.
        bad_prev_b += bytes([i ^ (16-byte_num) ^ prev_block[byte_num]])
        bad_prev_b += knownxor
        if (decryption_oracle(bad_prev_b + block)):
            return bytes([i])
    raise Exception

class TestPaddingAttack(unittest.TestCase):
    def test_challenge_17(self):
        random.seed(1)
        expected = b'000002Quick to the point, to the point, no faking'
        actual   = cbc_padding_attack()
        self.assertEqual(actual, expected)
        expected = b'000009ith my rag-top down so my hair can blow'
        actual   = cbc_padding_attack()
        self.assertEqual(actual, expected)
        expected = b'000001With the bass kicked in and the Vega\'s are pumpin\''
        actual   = cbc_padding_attack()
        self.assertEqual(actual, expected)

if __name__ == "__main__" :
    unittest.main()

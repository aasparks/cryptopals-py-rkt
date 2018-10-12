"""
**Challenge 12**

*Byte-at-a-time ECB Decryption (Simple)*

Copy your oracle function to a new function that encrypts under ECB mode
using a consistent but unknown key (for instance, assign a single random key,
once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

``Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK``

Base64 decode the string before appending it. Do not base64 decode the
string by hand; make your code do it. The point is that you don't know
its contents.

What you have now is a function that produces::

    AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the
oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time -- start
   with 1 byte ("A"), then "AA", then "AAA", and so on. Discover the block
   size of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step
   anyways.

3. Knowing the block size, craft an input block that is exactly 1 byte short
   (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
   what the oracle function is going to put in that last byte position.

4. Make a dictionary of every possible last byte by feeding different
   strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
   remembering the first block of each invocation.

5. Match the output of the one-byte-short input to one of the entries in
   your dictionary. You've now discovered the first byte of unknown-string.

6. Repeat for the next byte.
"""
import os, sys, unittest
from Crypto.Cipher import AES
sys.path.insert(0, '../set1')
import c1, c6, c9

key       = os.urandom(16)
unknown   = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
unknown   += b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
unknown   += b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown   = c1.base64toascii(unknown)

# Encryption oracle
def encryption_oracle(txt):
    """
    Black box encryption oracle that appends an unknown string to the given
    text, pads it out, and encrypts under AES-128-ECB with an unknown key.

    Args:
        txt: The plaintext to be encrypted.

    Returns:
        AES-128-ECB(txt || unknown-string, random-key) as a bytestring
    """
    return AES.new(key, AES.MODE_ECB).encrypt(c9.pkcs7_pad(txt + unknown))

# 1 Discover block size
def get_blocksize(oracle):
    """
    Gets the block size of encryption_oracle.

    Args:
        oracle: The encryption oracle function to be run.

    Returns:
        The block size that the encryption oracle is using (16)
    """
    # Send strings of length 0-40
    prev_len   = len(oracle(b''))
    for i in range(1, 40):
        ct = oracle(b'A' * i)
        # If the length increases by more than 1
        # we have jumped up a block
        if len(ct) > prev_len:
            return len(ct) - prev_len
    raise RuntimeError('Could not find block size')

# 2. Detect that the function is using ECB.
def is_ecb(oracle, blocksize):
    """
    Detects whether or not the given encryption oracle is using ECB mode

    Args:
        oracle: The encryption oracle
        blocksize: The block size of the oracle

    Returns:
        True if oracle is using ECB mode
    """
    ct = oracle(b'A' * blocksize * 3)
    return c6.get_block(ct, 0, blocksize) == c6.get_block(ct, 1, blocksize)

# 3. Craft an input block that is exactly 1 byte short of the block size
def craft_block(offset, num_bytes):
    """
    Crafts a block that is one byte short of the num_bytes - offset

    Args:
        offset: The number of bytes already known, that don't need to be crafted
        num_bytes: The number of bytes that need to be found in total

    Returns:
        A bytestring of all A's that is of length num_bytes - offset - 1
    """
    return b'A' * (num_bytes - 1 - offset)

# 4, 5
def decode_byte(known, num_bytes):
    """
    Decodes a single byte of the unknown string by trying every possible value

    Args:
        known: The parts of unknown-string that we already know
        num_bytes: The length of unknown-string

    Returns:
        The next decoded byte of unknown-string
    """
    # Just stop when we find the match. No need to save
    # a dictionary
    prefix   = craft_block(len(known), num_bytes)
    original = encryption_oracle(prefix)
    length   = len(prefix) + len(known) + 1
    for i in range(256):
        ct = encryption_oracle(prefix + known + bytes([i]))
        if (ct[:length] == original[:length]):
            return bytes([i])
    return None

# 6
def decode_secret():
    """
    Decodes unknown-string from the encryption oracle

    Returns:
        The decoded bytestring
    """
    e_secret  = encryption_oracle(b'')
    num_bytes = len(e_secret)
    secret    = []
    c         = ''

    # It may not be exactly num_bytes because of padding.
    # Run until we get back None
    c = decode_byte(b'', num_bytes)
    while c is not None:
        secret.append(c)
        c      = decode_byte(b''.join(secret), num_bytes)

    return b''.join(secret)

class TestECBByteAtATime(unittest.TestCase):
    def test_challenge_12(self):
        self.assertEqual(get_blocksize(encryption_oracle), 16)
        self.assertTrue(is_ecb(encryption_oracle, 16))
        secret = c9.pkcs7_unpad(decode_secret())
        self.assertEqual(secret, unknown)

if __name__ == "__main__" :
    unittest.main()

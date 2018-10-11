"""
Challenge 11
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just
16 random bytes.

Write a function that encrypts data under an unknown key ---
that is, a function that generates a random key and encrypts
under it.

The function should look like
   encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes before the
plaintext and 5-10 bytes after the plaintext.

Now have the function choose to encrypt under ECB 1/2 the time,
and under CBC the other half (just use random IV's each time
for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You
should end up with a piece of code that, pointed at a black box
that might be encrypting ECB or CBC, tells which one is happening.
"""
from Crypto.Cipher import AES
import os, random, sys, unittest
sys.path.insert(0, '../set1/')
import c1, c8, c9, c7, c10

# For testing, let's save which mode was used each time.
# ECB = True
# CBC = False
expected = []

# ENCRYPT using an unknown mode with random data inserted
def encryption_oracle(txt):
    global expected
    # GENERATE random key
    key    = os.urandom(16)
    # GENERATE random number for ECB or CBC
    ecb    = bool(random.getrandbits(1))
    expected.append(ecb)
    # APPEND random bytes before and after
    before = os.urandom(random.randint(5, 10))
    after  = os.urandom(random.randint(5, 10))
    txt    = before + txt + after
    txt    = c9.pkcs7_pad(txt)
    ct     = b''
    # IF CBC
    if not ecb:
        # GENERATE random IV
        iv = os.urandom(16)
        ct = c10.aes_128_cbc_encrypt(txt, key, iv)
    # ENCRYPT
    else:
        ct = AES.new(key, AES.MODE_ECB).encrypt(txt)
    return ct

# Determines if the encryption is ECB or CBC
# There's a few questions here. Can we detect CBC mode
# easily like we can with ECB? Not really. But it is safe
# to assume that ECB and CBC are the only ones being used
# (because they are). Assuming the plaintext is large enough
# and, more importantly, includes repeated blocks of 16-bytes,
# we can safely detect ECB. Of couse this would probably not
# work for a small plaintext.
def ecb_or_cbc(txt):
    """
    Determines if the given ciphertext was encrypted with ECB or CBC.

    Args:
        txt: The ciphertext in question

    Returns:
        True if using ECB, False if using CBC.
    """
    return c8.is_ecb(txt, 1)

class TestECBOrCBC(unittest.TestCase):
    def setUp(self):
        f = open('../../testdata/10.txt')
        self.ctxt = c1.base64toascii(f.read())
        self.key  = b'YELLOW SUBMARINE'
        self.pt   = c10.aes_128_cbc_decrypt(self.ctxt, self.key)
        f.close()
    def test_challenge_11(self):
        result = []
        for i in range(50):
            ct = encryption_oracle(self.pt)
            result.append(ecb_or_cbc(ct))
        self.assertEqual(result, expected)

if __name__ == "__main__":
    unittest.main()

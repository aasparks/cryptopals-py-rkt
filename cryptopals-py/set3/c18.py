"""
**Challenge 18**

*Implement CTR, the Stream Cipher Mode*

The given string decrypts to something approximating English
in CTR mode, which is an AES block cipher mode that turns AES into
a stream cipher, with the following parameters::

    key=YELLOW SUBMARINE
    nonce=0
    format=64 bit unsigned little endian nonce
           64 bit little endian block count

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running
counter, producing a 16-byte block of keystream, which is XOR'd
against the plaintext.

CTR mode does not require padding; when you run out of plaintext, you
just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR,
and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR
function to encrypt and decrypt other things.
"""
from Crypto.Cipher import AES
import sys, struct, unittest
sys.path.insert(0, '../set1')
import c1, c2

def __little_endian(num):
    return struct.pack('<Q', num)

def aes_128_ctr(txt, key, nonce = 0):
    """
    Encrypts the given txt under AES-128 in CTR mode with the given key and
    a nonce.

    Args:
        txt: The text to encrypt
        key: The key to encrypt under
        nonce (optional): The nonce for CTR mode

    Returns:
        The encrypted txt.
    """
    num_blocks = (len(txt) // 16) + 1
    keystream  = b''
    for i in range(num_blocks):
        val = __little_endian(nonce) + __little_endian(i)
        keystream += AES.new(key, AES.MODE_ECB).encrypt(val)
    return c2.xorstrs(txt, keystream[:len(txt)])

class TestCTR(unittest.TestCase):
    def test_challenge_18(self):
        txt = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
        key = b'YELLOW SUBMARINE'
        pt  = aes_128_ctr(c1.base64toascii(txt), key, 0)
        expected = b'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby '
        self.assertEqual(pt, expected)

if __name__ == "__main__" :
    unittest.main()

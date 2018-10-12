"""
**Challenge 7**

*AES in ECB mode*

The base64-encoded content in this file has been encrypted via
AES-128 in ECB mode under the key

``"YELLOW SUBMARINE"``

(case-sensitive, without the quotes; exactly 16 characters).

Decrypt it. You know the key, after all.
"""
from Crypto.Cipher import AES
import c1
import unittest

## Uses the AES library function to decrypt
def aes_128_ecb_decrypt(txt, key):
    """
    Decrypts AES-128 under ECB mode.

    Args:
        txt: The ciphertext to be decrypted.
        key: The key for decryption

    Returns:
        The decrypted plaintext.
    """
    return AES.new(key, AES.MODE_ECB).decrypt(txt)

## Uses the AES library function to encrypt
def aes_128_ecb_encrypt(txt, key):
    """
    Encrypts AES-128 under ECB mode.

    Args:
        txt: The plaintext to be encrypted.
        key: The key for encryption

    Returns:
        The encrypted ciphertext.
    """
    return AES.new(key, AES.MODE_ECB).encrypt(txt)

class TestAESECB(unittest.TestCase):
    def setUp(self):
        self.DEBUG = False
        f          = open('../../testdata/7.txt')
        self.txt   = c1.base64toascii(f.read())
        f.close()
        self.key = b'YELLOW SUBMARINE'
    def test_challenge_7(self):
        result = aes_128_ecb_decrypt(self.txt, self.key)
        if self.DEBUG:
            print(result)
        enc = aes_128_ecb_encrypt(result, self.key)
        self.assertEqual(enc, self.txt)

if __name__ == '__main__' :
    unittest.main()

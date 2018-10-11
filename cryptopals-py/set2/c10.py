"""
Challenge 10
Implement CBC Mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
messages, despite the fact that a block cipher natively only transforms
individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block
before the next call to the cipher core.
The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector,
or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making
it encrypt instead of decrypt, and using your XOR function from the previous
exercise to combine them.

The file here is intelligible when CBC decrypted against "YELLOW SUBMARINE"
with an IV of all ASCII 0.
"""
from Crypto.Cipher import AES
import sys, unittest
sys.path.insert(0, '../set1')
import c1, c2, c6, c7, c9

## CBC Mode encryption  works by XORing the previous block with
## the plaintext before encrypting it.
## Ci = E(Pi ^ Ci-1)
def aes_128_cbc_encrypt(txt, key, IV=b'\x00'*16):
    """
    Encrypts a bytestring under AES-128 in CBC mode

    Args:
        txt: The plaintext to be encrypted
        key: The key to encrypt under
        iv: The initialization vector

    Returns:
        The encrypted text under AES-128 in CBC mode.
    """
    # Assert all size constraints
    if len(txt) % 16 != 0:
        raise ValueError('Input length must be a multiple of 16, got ' + str(len(txt)))
    if len(key) != 16:
        raise ValueError('Key must be length 16, got ' + str(len(key)))
    if len(IV) != 16:
        raise ValueError('IV must be length 16, got ' + str(len(IV)))
    num_blocks = len(txt) // 16
    prev_block = IV
    result     = []
    # Loop through each block, XORing with the previous
    for i in range(num_blocks):
        cur_block  = c6.get_block(txt, i, 16)
        cur_block  = c2.xorstrs(prev_block, cur_block)
        cur_block  = c7.aes_128_ecb_encrypt(cur_block, key)
        prev_block = cur_block
        result.append(prev_block)
    return b''.join(result)

## Decrypt works backwards
## Pi = D(Ci) ^ Ci-1
def aes_128_cbc_decrypt(txt, key, IV=b'\x00'*16):
    """
    Decrypts the given bytestring using AES-128 in CBC mode

    Args:
        txt: The text to be decrypted
        key: The encryption key
        iv: The initialization vector

    Returns:
        The decrypted bytestring.
    """
    # Assert all size constrains
    if len(txt) % 16 != 0:
        raise ValueError('Input length must be a multiple of 16, got ' + str(len(txt)))
    if len(key) != 16:
        raise ValueError('Key must be length 16, got ' + str(len(key)))
    if len(IV) != 16:
        raise ValueError('IV must be length 16, got ' + str(len(IV)))
    num_blocks = len(txt) // 16
    prev_block = IV
    result     = []
    # Loop through each block, XORing with the previous
    for i in range(num_blocks):
        cur_block  = c6.get_block(txt, i, 16)
        temp       = cur_block
        cur_block  = c7.aes_128_ecb_decrypt(cur_block, key)
        cur_block  = c2.xorstrs(cur_block, prev_block)
        prev_block = temp
        result.append(cur_block)
    return b''.join(result)

class TestCBCMode(unittest.TestCase):
    def setUp(self):
        f          = open('../../testdata/10.txt')
        self.ctxt  = c1.base64toascii(f.read())
        f.close()
        self.key   = b'YELLOW SUBMARINE'
        self.iv    = b'\x00' * 16
        self.DEBUG = False
    def smoke_test(self):
        pt  = b'Who lives in a pineapple under the sea?'
        pt  = c9.pkcs7_pad(pt)
        key = b'YELLOW SUBMARINE'
        ct  = aes_128_cbc_encrypt(pt, key)
        pt2 = aes_128_cbc_decrypt(ct, key)
        self.assertEqual(pt, pt2)

    def test_challenge_10(self):
        pt = aes_128_cbc_decrypt(self.ctxt, self.key, self.iv)
        # To see the result, set DEBUG to true
        if self.DEBUG:
            print(c9.pkcs7_unpad(pt))

if __name__ == '__main__' :
    unittest.main()

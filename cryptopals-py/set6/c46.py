"""
**Challenge 46**

*RSA Parity Oracle*

Generate a 1024-bit RSA key pair.

Write an oracle function that uses the private key to answer the question
"is the plaintext of this message even or odd" (is the last bit of the message
0 or 1). Imagine or instance a server that accepted RSA-encrypted messages and
checked the parity of their decryption to validate them, and spat out an error
if they were of the wrong parity.

Anyways: function returning true or false based on whether the decrypted
plaintext was even or odd, and nothing else.

Take the following string and un-base64 it in your code (without looking at it!)
and encrypt it to the public key, creating a ciphertext::

   VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ

With your oracle function, you can trivially decrypt the message.

Here's why:

   * RSA ciphertexts are just numbers. You can do trivial math on them. You can
     for instance multiply a ciphertext by the RSA-encryption of another number;
     the corresponding plaintext will be the product of those two numbers.
   * If you double a ciphertext (multiply it by (2**e)%n), the resulting
     plaintext will (obviously) be either even or odd.
   * If the plaintext after doubling is even, doubling the plaintext didn't wrap
     the modulus --- the modulus is a prime number. That means the plaintext is
     less than half the modulus.

You can repeatedly apply this heuristic, once per bit of the message, checking
your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the upper bound
is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration; you'll see
the message decrypt "hollywood sytle".

Decrypt the string (after encrypting it to a hidden private key) above.
"""
import sys, unittest
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set5')
import c39, c1
from Crypto.Util import number

def is_odd(ctxt, priv):
    """
    Determines if the number is odd

    Args:
        ctxt: Ciphertext to decrypt and check

    Returns:
        True if the RMB is set
    """
    num = c39.rsa_decrypt(ctxt, priv)
    num = number.bytes_to_long(num)
    return (num & 1) == 1

def decrypt_msg(ctxt, pub, priv):
    e, n = pub
    low  = 0
    high = n
    num = number.bytes_to_long(ctxt)
    double = pow(2, e, n)

    for i in range(n.bit_length()):
        num = (num * double) % n
        mid = (low + high) // 2
        if is_odd(number.long_to_bytes(num), priv):
            low = mid
        else:
            high = mid
    return number.long_to_bytes(high)

def decrease_range(num, pub, priv, low, high):
    e,n = pub
    double_num =  num * pow(2, e, n)
    if num == 0:
        return high
    if is_odd(double_num):
        low = (low + high) // 2
    else:
        print(number.long_to_bytes(high))
        high = high // 2
    return decrease_range(num >> 1, pub, low, high)

class TestChallenge45(unittest.TestCase):
    def setUp(self):
        msg = b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb'
        msg += b'3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
        self.msg = c1.base64toascii(msg)
    def test_challenge_46(self):
        pub, priv = c39.rsa_keygen(bit_len=1024)
        ctxt = c39.rsa_encrypt(self.msg, pub)
        ptxt = decrypt_msg(ctxt, pub, priv)
        self.assertEqual(ptxt[:-1], self.msg[:-1])

if __name__ == "__main__":
    unittest.main()
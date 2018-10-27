"""
**Challenge 39**

*Implement RSA*

There are two annoying things about implementing RSA. Both of them involve key
generation; the actual encryption/decryption in RSA is trivial.

First, you need to generate random primes. You can't just agree on a prime
ahead of time, like you do in DH. You can write this algorithm yourself, but I
just cheat and use OpenSSL's BN library to do the work.

The second is that you need an 'invmod' operation (the multiplicative inverse),
which is not an operation that is wired into your language. The algorithm is
just a couple lines, but I always lose an hour getting it to work.

I recommend you not bother with primegen, but do take the time to get your own
EGCD and invmod algorithm working.

Now:

* Generate 2 random primes. We'll use small numbers to start, so you can just
  pick them out of a prime table. Call them 'p' and 'q'.
* Let n be p * q. You RSA math is modulo n.
* Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
* Let e be 3.
* Compute d=invmod(e, et). invmod(17, 3120) is 2753.
* Your public key is [e,n]. Your private key is [d,n].
* To encrypt: c = m**e % n. To decrypt: m = c**d % n
* Test this out with a number, like "42".
* Repeat with bignum primes (keep e = 3)

Finally, to encrypt a string, do something cheesy, like convert the string to
hex and put "0x" on the front of it to turn it into a number. The math cares
not how stupidly you feed it strings.
"""
from Crypto.Util import number
import unittest
import c36

def primegen(bit_len=2048):
    """
    Generates a large prime number.

    Args:
        bit_len (integer : 2048): The bit length of the number you want

    Returns:
        A prime number of size bit_len bits
    """
    return number.getPrime(bit_len)

def invmod(num, mod):
    """
    Performs the multiplicative inverse. I originally wrote invmod (along with)
    xgcd myself, but it was just from Rosetta Code, so what's the point?

    Args:
        num: The number for invert
        mod: The modulus

    Returns:
        Inverse mod of num.
    """
    return number.inverse(num, mod)

def rsa_primegen(e):
    """
    Generates a large prime number for RSA. There is a restriction here such
    that (p-1) % e != 0, so this function checks for that.

    Args:
        e: RSA exponent

    Returns:
        A large prime number for RSA.
    """
    p = primegen()
    while (p-1) % e == 0:
        p = primegen()
    return p

def rsa_keygen():
    """
    Performs the RSA math and gives back the public and private keys.

    Returns:
        The pair (pub-key, priv-key).
    """
    e    = 3
    p, q = rsa_primegen(e), rsa_primegen(e)
    n    = p * q
    et   = (p-1) * (q-1)
    d    = invmod(e, et)
    pub  = [e, n]
    priv = [d, n]
    return pub, priv

def rsa_encrypt(message, key):
    """
    Performs encryption using an RSA key.

    Args:
        message (bytes): The message to encrypt
        key (int,int): The RSA key as a pair

    Returns:
        The encrypted message
    """
    m = number.bytes_to_long(message)
    c = pow(m, key[0], key[1])
    return number.long_to_bytes(c)

def rsa_decrypt(ctxt, key):
    """
    Performs decryption using RSA.

    Args:
        ctxt (bytes): The encrypted message
        key (int, int): The RSA key as a pair
    """
    # It's the same math
    return rsa_encrypt(ctxt, key)

class TestRSA(unittest.TestCase):
    def test_invmod(self):
        self.assertEqual(invmod(17, 3120), 2753)
        self.assertEqual(invmod(42, 2017), 1969)

    def test_rsa_encrypt(self):
        pub, priv = rsa_keygen()
        message   = b'Attack at dawn!'
        e_msg     = rsa_encrypt(message, pub)
        d_msg     = rsa_decrypt(e_msg, priv)
        self.assertEqual(d_msg, message)

    def test_keygen(self):
        pub, priv = rsa_keygen()
        pub1, priv1 = rsa_keygen()
        self.assertNotEqual(pub, pub1)
        self.assertNotEqual(priv, priv1)

if __name__ == "__main__":
    unittest.main()

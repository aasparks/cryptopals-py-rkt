"""
**Challenge 33**

*Implement Diffie-Hellman*

For one of the most important algorithms in cryptography,
this exercise couldn't be a whole lot easier.

Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm
not even going to explain it. Just do what I do.

Generate "a", a random number mod 37. Now generate "A", which is "g"
raised to the "a" power mod 37 -- ``A = (g**a) % p``

Do the same for "b" and "B"

"A" and "B" are public keys. Generate a session key with them;
set "s" to "B" raised to the "a" power mod 37 --- ``s = (B**a) % p``

Do the same with A**b, check that you come up with the same "s".

To turn "s" into a key, you can just hash it to create 128 bits of
key material.

Ok, that was fun, now repeat the exercise with bignums like
in the real world. Here are parameters NIST likes::

    p:
      ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
      e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
      3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
      6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
      24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
      c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
      bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
      fffffffffffff
    g: 2

This is very easy to do in Python or Ruby or other high-level
languages that auto-promote fixnums to bignums, but it isn't
"hard" anywhere.
"""
import random, os, sys, unittest
sys.path.insert(0, '../set4')
import MYSHA1


def diffie_hellman(p, g):
    """
    Runs the simple Diffie-Hellman math on p and g to generate
    the public/private keys

    Args:
        p: prime number use as the modulus
        g: generator

    Returns:
        The private and public key pair denoted as a,A or b,B
    """
    a = random.randint(0, p-1)
    A = pow(g, a, p)
    return a, A

def make_session_key(pub, priv, p):
    """
    Makes a DH session key from the public, private pair

    Args:
        pub: public key value (A or B)
        priv: private key value (b or a)
        p: prime number used as the modulus

    Returns:
        The session key made from SHA1(pub**priv % p)
    """
    s       = pow(pub, priv, p)
    s_bytes = str(s).encode()
    return MYSHA1.MYSHA1(s_bytes).digest()

class TestDH(unittest.TestCase):
    def test_challenge_33(self):
        p = '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        p += 'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        p += '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        p += '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        p += '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        p += 'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        p += 'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        p += 'fffffffffffff'
        p = int(p, 16)
        g = 5
        a,A = diffie_hellman(p, g)
        b,B = diffie_hellman(p, g)
        self.assertNotEqual(a, b)
        self.assertNotEqual(A, B)
        s1 = make_session_key(A,b,p)
        s2 = make_session_key(B,a,p)
        self.assertEqual(s1, s2)

if __name__ == "__main__":
    unittest.main()
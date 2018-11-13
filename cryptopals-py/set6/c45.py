"""
**Challenge 45**

*DSA Parameter Tampering*

Take your DSA code from the previous exercise. Imagine it as part of an
algorithm in which the client was allowed to propose domain parameters (the
p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting bad
parameters. Vaudenay gave two examples of bad generator parameters: generators
that were 0 mod p, and generators that were 1 mod p.

Use the parameters from the previous exercise, but substitute 0 for 'g'.
Generate a signature. You will notice something bad. Verify the signature. Now
verify any other signature, for any other string.

Now, try (p+1) as 'g'. With this 'g', you can generate a magic signature s,r
for any DSA public key that will validate against any string. For arbitrary z::

       r = ((y**) % p) % q
            r
       s = --- % q
            z

Sign "Hello, world". And "Goodbye, world".
"""
import sys, unittest
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set5')
import c1, c43, c39
from Crypto.Util import number

class TestChallenge43(unittest.TestCase):
    def setUp(self):
        p = b'800000000000000089e1855218a0e7dac38136ffafa72eda7'
        p += b'859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
        p += b'2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
        p += b'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
        p += b'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
        p += b'1a584471bb1'
        p = number.bytes_to_long(c1.hextoascii(p))

        q = b'f4f47f05794b256174bba6e9b396a7707e563c5b'
        q = number.bytes_to_long(c1.hextoascii(q))

        g = 0
        y =  b'084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        y += b'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        y += b'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        y += b'1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        y += b'bb283e6633451e535c45513b2d33c99ea17'

        self.params = p,q,g
        self.pub = number.bytes_to_long(c1.hextoascii(y))

    def test_g_0(self):
        msg  = b'Hello, world'
        sig = c43.dsa_sign(msg, self.params, self.pub)
        r,s = sig
        self.assertEqual(r, 0)
        self.assertTrue(c43.dsa_verify(msg, sig, self.params, self.pub))
        sig2 = c43.dsa_sign(b'hej hej monika', self.params, self.pub)
        self.assertTrue(c43.dsa_verify(msg, sig, self.params, self.pub))

    def test_challenge_45(self):
        p,q,g = self.params
        g = p+1
        self.params = p,q,g
        msg = b'Hello, world'
        sig = forge_signature(msg, self.params, self.pub)
        self.assertTrue(c43.dsa_verify(msg, sig, self.params, self.pub))
        msg = b'Goodbye, world'
        sig = forge_signature(msg, self.params, self.pub)
        self.assertTrue(c43.dsa_verify(msg, sig, self.params, self.pub))

def forge_signature(msg, params, y):
    p,q,g = params
    z = number.bytes_to_long(msg)
    r = pow(y, z, p) % q
    s = (r * c39.invmod(z,q)) % q
    return r,s

if __name__ == "__main__":
    unittest.main()
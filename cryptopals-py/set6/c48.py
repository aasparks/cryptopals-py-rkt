"""
**Challenge 48**

*Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)*

This is a continuation of challenge #47; it implements the complete BB'98 attack.

Set yourself up the way you did in #47, but this time generate a 768 bit modulus.

To make the attack work with a realistic RSA keypair, you need to reproduce step
2b from the paper, and your implementation of Step 3 needs to handle multiple
ranges.

The full Bleichenbacher attack works basically like this:
    * Starting from the smallest 's' that could possibly produce a plaintext
      bigger than 2B, iteratively search for an 's' that produces a conformant
      plaintext.
    * For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition of
      modular multiplication) for 'r', the number of times we've wrapped the
      modulus.
    * 'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5
      plaintexts, and so are between [2B,3B].
    * We substitute the known bounds for both, leaving only 'r' free, and solve
      for a range of possible 'r' values. This range should be small!
    * Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of
      'r' we generated in the last step. This gives us new intervals to work
      with. Rule out any interval that is outside 2B,3B.
    * Repeat the process for successively higher values of 's'. Eventually, this
      process will get us down to just one interval, whereupon we're back to
      exercise #47.

What happens when we get down to one interval is, we stop blindly incrementing
's'; instead, we start rapidly growing 'r' and backing it out to 's' values by
solving m1=m0s1-rn for 's' instead of 'r' or 'm0'. So much algebra! Make your
teenage son do it for you! *Note: does not work well in practice*
"""
import os, sys, unittest
sys.path.insert(0, '../set5')
sys.path.insert(0, '../set6')
import c39, c47
from Crypto.Util import number

# So I did this for c47 already. Let's just run it. It takes longer.

class TestChallenge48(unittest.TestCase):
    def setUp(self):
        pub, priv  = c39.rsa_keygen(bit_len=768)
        self.pub   = pub
        self.priv  = priv
        c47.G_PRIV = priv
        #c47.DEBUG = true
        self.msg   = b'kick it, CC'

    def test_rsa(self):
        ctxt = c39.rsa_encrypt(self.msg, self.pub)
        ptxt = c39.rsa_decrypt(ctxt, self.priv)
        self.assertEqual(self.msg, ptxt)

    def test_pad(self):
        e, n = self.pub
        padd = c47.pkcs15_pad(self.msg, n)
        ctxt = c39.rsa_encrypt(padd, self.pub)
        self.assertTrue(c47.padding_oracle(number.bytes_to_long(ctxt)))

    def test_attack(self):
        e, n    = self.pub
        padd    = c47.pkcs15_pad(self.msg, n)
        ctxt    = c39.rsa_encrypt(padd, self.pub)
        decoded = c47.attack_rsa(number.bytes_to_long(ctxt), self.pub)
        self.assertEqual(decoded, padd)


if __name__ == "__main__":
    unittest.main()

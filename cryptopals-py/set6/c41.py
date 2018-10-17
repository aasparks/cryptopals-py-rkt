"""
**Challenge 41**

*Implement Unpadded Message Recovery Oracle*

Nate Lawson says we should stop calling it "RSA padding" and start calling it
"RSA armoring". Here's why.

Imagine a web application, again with the Javascript encryption, taking
RSA-encrypted messages which (again: Javascript) aren't padded before encryption
at all.

You can submit an arbitrary RSA blob and the server will return plaintext. But
you can't submit the same message twice; let's say the server keeps hashes of
previous messages for some liveness interval, and that the message has an
embedded timestamp::

    {
        time: 1356304276,
        social: '555-55-5555'
    }

You'd like to capture other people's messages and use the server to decrypt
them. But when you try, the server takes the hash of the ciphertext and uses it
to reject the request. Any bit you flip in the ciphertext irrevocably scrambles
the decryption.

This turns out to be trivially breakable:

* Capture the ciphertext C
* Let N and E be the public modulus and exponent respectively
* Let S be a random number > 1 mod N. Doesn't matter what.
* Now::

    C' =((S**E mod N) C) mod N

* Submit C', which appears totally different from C, to the server, recovering
  P', which appears totally different from P
* Now::

    P = modinv(P', S) mod N

Oops!

Implement that attack.
"""
import os, sys, random, unittest
sys.path.insert(0, '../set5')
import c36, c39

class UnpaddedRSAServer():
    """
    Represents a server that does not pad its messages. I'm leaving out all the
    hashing and timestamp logic because it's a waste of time. Just doing
    the attack on a simple server.
    """
    def __init__(self):
        self.pub, self.priv = c39.rsa_keygen()
        print(self.pub)
        print(self.priv)

    def encrypt_msg(self, message):
        ctxt = c39.rsa_encrypt(message, self.pub)
        return ctxt, self.pub

    def decrypt_msg(self, message):
        ptxt = c39.rsa_decrypt(message, self.priv)
        return ptxt

def attack_server(server, msg):
    ctxt, pub = server.encrypt_msg(msg)
    N, E      = pub
    S         = random.randint(1, N**2) % N
    c_prime   = pow(S, E, N) * int.from_bytes(ctxt, 'big') % N
    p_prime, pub   = server.encrypt_msg(c36.int_to_bytes(c_prime))
    p         = c39.invmod(int.from_bytes(p_prime, 'big'), S) % N
    return c36.int_to_bytes(p)

class TestPaddingAttack(unittest.TestCase):
    def test_server(self):
        server = UnpaddedRSAServer()
        msg    = b'Attack at dawn!'
        ctxt, pub   = server.encrypt_msg(msg)
        ptxt   = server.decrypt_msg(ctxt)
        self.assertEqual(ptxt, msg)
        self.assertNotEqual(ctxt, msg)

    def test_challenge_41(self):
        msg  = b'Attack at dawn!'
        server = UnpaddedRSAServer()
        p = attack_server(server, msg)
        self.assertEqual(p, msg)


if __name__ == "__main__":
    unittest.main()

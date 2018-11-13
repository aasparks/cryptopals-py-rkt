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

    P = P' * modinv(S, N) mod N

Oops!

Implement that attack.
"""
import os, sys, random, unittest
from hashlib import sha256
from Crypto.Util import number
sys.path.insert(0, '../set5')
import c36, c39

class UnpaddedRSAServer():
    """
    Represents a server that does not pad its messages. But it does save a hash
    of the ciphertexts so no plaintexts can be sent twice. They don't expire
    though, because the server is obviously not running all the time.
    """
    def __init__(self):
        self.pub, self.priv = c39.rsa_keygen()
        self.msgs = []

    def encrypt_msg(self, message):
        """
        Encrypts the given message under the server's public key.

        Args:
            message: The message to encrypt

        Returns:
            The encrypted message
        """
        ctxt = c39.rsa_encrypt(message, self.pub)
        return ctxt, self.pub

    def decrypt_msg(self, message):
        """
        Decrypts the given ciphertext but only if it has not been decrypted
        once already.

        Args:
            message: The message to decrypt

        Returns:
            The decrypted ciphertext.

        Raises:
            ValueError if the message has been decrypted already
        """
        hash_msg = sha256(message).digest()
        if hash_msg in self.msgs:
            raise ValueError("Message already seen")
        self.msgs.append(hash_msg)
        ptxt = c39.rsa_decrypt(message, self.priv)
        return ptxt

def attack_server(server, msg):
    """
    Attacks the RSA server using the attack described in the problem.

    Args:
        server: The server to attack
        msg: The message to use to attack the server

    Returns:
        The decrypted plaintext (even though it aleady has it)
    """
    ctxt, (E, N) = server.encrypt_msg(msg)
    ptxt         = server.decrypt_msg(ctxt)
    assert(ptxt == msg)
    S         = random.randint(2, N-1)
    c_prime   = (pow(S, E, N) * number.bytes_to_long(ctxt)) % N
    p_prime   = server.decrypt_msg(number.long_to_bytes(c_prime))
    p         = (number.bytes_to_long(p_prime) * c39.invmod(S, N)) % N
    return number.long_to_bytes(p)

class TestPaddingAttack(unittest.TestCase):
    def test_server(self):
        server    = UnpaddedRSAServer()
        msg       = b'Attack at dawn!'
        ctxt, pub = server.encrypt_msg(msg)
        ptxt      = server.decrypt_msg(ctxt)
        self.assertEqual(ptxt, msg)
        self.assertNotEqual(ctxt, msg)
        with self.assertRaises(ValueError):
            server.decrypt_msg(ctxt)

    def test_challenge_41(self):
        msg    = b'Attack at dawn!'
        server = UnpaddedRSAServer()
        p      = attack_server(server, msg)
        self.assertEqual(p, msg)


if __name__ == "__main__":
    unittest.main()

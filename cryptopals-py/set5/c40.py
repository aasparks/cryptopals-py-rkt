"""
**Challenge 40**

*Implement an E=3 RSA Broadcast Attack*

Assume you're a Javascript programmer. That is, you're using a naive handrolled
RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three times, under
three different public keys. You can; it's happened.

Then an attacker can trivially decrypt your message, by:

1. Capturing any 3 of the ciphertexts and their corresponding pubkeys
2. Using the CRT to solve for the number represented by the three ciphertexts
   (which are residues mod their respective pubkeys)
3. Taking the cube root of the resulting number

The CRT says you can take any number and represent it as the combination of a
series of residues mod a series of moduli. In the three-residue case, you have::

    result =
        (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
        (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
        (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

where::

    c_0, c_1, c_2 are the three respective residues mod n_0, n_1, n_2
    m_s_n (for n in 0, 1, 2) are the product of the moduli EXCEPT n_n
        ie, m_s_1 is n_0 * n_2
    n_012 is the product of all three moduli

To decrypt the RSA using a simple cube root, leave off the final modulus
operation; just take the raw accumulated result and cube-root it.
"""
import c36, c39, unittest
class BadRSAServer():
    """
    Simulates a dumb server that encrypts with a new RSA key pair and returns
    the ciphertext with the public key.

    Args:
        message: The message to encrypt

    Returns:
        The pair (ciphertext, public-key) where public-key is a pair containing
        (e, n)
    """
    def encrypt_message(self, message):
        pub, priv = c39.rsa_keygen()
        ctxt = c39.rsa_encrypt(message, pub)
        return ctxt, pub

def attack_rsa(message):
    """
    Performs the e=3 broadcast attack as described above.

    Args:
        message (bytes): The message to send 3 times.

    Returns:
        The message that was sent in, but decrypted from the crazy math.
    """
    server = BadRSAServer()
    c_0, (_, n_0) = server.encrypt_message(message)
    c_1, (_, n_1) = server.encrypt_message(message)
    c_2, (_, n_2) = server.encrypt_message(message)

    m_0 = n_1 * n_2
    m_1 = n_0 * n_2
    m_2 = n_0 * n_1
    c_0 = int.from_bytes(c_0, 'big')
    c_1 = int.from_bytes(c_1, 'big')
    c_2 = int.from_bytes(c_2, 'big')

    result = c_0 * m_0 * c39.invmod(m_0, n_0)
    result += c_1 * m_1 * c39.invmod(m_1, n_1)
    result += c_2 * m_2 * c39.invmod(m_2, n_2)
    result = result % (n_0 * n_1 * n_2)

    result = find_invpow(result, 3)[0]
    return c36.int_to_bytes(result)

def find_invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    Stolen from Wiki.

    Args:
        x (int): The number to get the n'th root for
        n (int): The n'th root

    Returns:
        The pair of (floor, ceiling) of the n'th root of x
    """
    guess = 1
    step = 1
    while 1:
        w = (guess+step)**n
        if w == x:
            return (guess+step,) * 2
        elif w < x:
            step <<= 1
        elif step == 1:
            return guess, guess+1
        else:
            guess += step >> 1
            step = 1

class TestRSABroadcastAttack(unittest.TestCase):
    def test_rsa_attack(self):
        msg = b'Attack at dawn!'
        self.assertEqual(attack_rsa(msg), msg)

if __name__ == "__main__":
    unittest.main()
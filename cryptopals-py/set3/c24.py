"""
**Challenge 24**

*Create the MT19937 Stream Cipher and Break It*

You can create a trivial stream cipher out of any PRNG; use it to generate a
sequence of 8-bit outputs and call those outputs a keystream. XOR each byte of
plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that
you can encrypt and decrypt properly. This code should look similar to your
CTR code.

Use your function to encrypt a known plaintext (say, 14 A's prefixed by a
random number of random characters)

From the ciphertext, recover the 'key' (the seed).

Use the same idea to generate a random "password reset token" using MT19937
seeded from the current time.

Write a function to check if any given password token is actually the product
of an MT19937 PRNG seeded with the current time.
"""
import sys, os, random, time, unittest
sys.path.insert(0, '../set1')
import c2, c21

def encrypt(txt, seed):
    """
    Encrypts the given text using MT19937 to create a stream cipher.

    Args:
        txt: The text to be encrypted.
        seed: The seed for the MT19937.

    Returns:
        The encrypted text.
    """
    mt        = c21.MT19937(seed)
    num_bytes = len(txt)
    keystream = []
    for i in range(num_bytes):
        keystream.append(bytes([mt.generate_number() & 0xFF]))
    return c2.xorstrs(txt, b''.join(keystream))

def decrypt(txt, seed):
    """
    Decrypts the txt that was encrypted with the MT19937. It works the same
    as encrypt, so it just calls encrypt(txt, seed).

    Args:
        txt: The text to be decrypted.
        seed: The seed for MT19937.

    Returns:
        The decrypted text.
    """
    return encrypt(txt, seed)

def encryption_oracle(txt, seed=123):
    """
    Encrypts the given text with a random prefix, using MT19937 stream cipher.

    Args:
        txt: The text to be encrypted.
        seed (optional): The seed to use for encryption

    Returns:
        The encryption of prefix + txt under MT19937 stream cipher.
    """
    prefix = os.urandom(random.randint(10, 20))
    return encrypt(prefix + txt, seed)

def get_seed(oracle):
    """
    Gets the seed that is being used by the oracle.

    Args:
        oracle: encryption oracle function

    Return:
        The MT19937 stream cipher seed

    Raises:
        RuntimeError if seed is not found
    """
    orig    = b'A' * 14
    orig_ct = oracle(orig)
    for i in range(2**16):
        pt = decrypt(orig_ct, i)
        if pt[-14:] == orig:
            return i
    raise RuntimeError('seed not found')

def password_reset():
    """
    Generates a password reset token using the MT19937 seeded with the current
    time.

    Returns:
        A bytestring containing the password reset token.
    """
    seed  = int(time.time())
    mt    = c21.MT19937(seed)
    token = []
    for i in range(6):
        token.append(bytes([mt.generate_number() & 0xFF]))
    return b''.join(token)

def is_valid_token(token):
    """
    Determines if the given token was created by seeding an MT19937 with
    the current time.

    Args:
        token: The password reset token in question

    Returns:
        True if token was generated with MT19937.
    """
    start_seed = int(time.time())
    # Don't go too far back
    for i in range(2000):
        mt      = c21.MT19937(start_seed - i)
        n_token = []
        for i in range(6):
            n_token.append(bytes([mt.generate_number() & 0xFF]))
        if b''.join(n_token) == token:
            return True
    return False

class TestMTStreamCipher(unittest.TestCase):
    def test_cipher(self):
        orig = os.urandom(14)
        orig += b'A' * 14
        ct   = encrypt(orig, 455)
        pt   = decrypt(ct, 455)
        self.assertEqual(pt, orig)

    def test_get_seed(self):
        self.assertEqual(get_seed(encryption_oracle), 123)

    def test_challenge_24(self):
        self.assertTrue(is_valid_token(password_reset()))

if __name__ == "__main__" :
    unittest.main()

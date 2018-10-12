"""
Challenge 27
Recover the key from CBC with IV=KEY

Take your code from exercise 16 and modify it so that it uses the key for CBC
encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the
sender and the receiver have to know the key already, and can save some space
by using it as both the key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in
flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the
plaintext for ASCII compliance. Noncompliant messages should raise an exception
or return an error that includes the decrypted plaintext.

Use your code to encrypt a message that is at least 3 blocks long:
    AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message to:
    C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message and raise the appropriate error.

As the attacker, recovering the plaintext from the error, extract the key:
    P'_1 ^ P'_3
"""
import sys, os, unittest
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
sys.path.insert(0, '../set3')
import c2, c6, c9, c10

key    = os.urandom(16)
prefix = b'comment1=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

def encrypt_userdata(data):
    """
    Encrypts the given data under AES-128-CBC with a secret key, after
    appending and prepending data and quoting out metacharacters. This function
    uses the key as the IV as well.

    Args:
        data: The user data to be encrypted

    Returns:
        AES-128-CBC(prefix || user-data || suffix, random-key, iv=random-key)
    """
    new_c  = prefix + data.replace(b';', b'').replace(b'=', b'') + suffix
    new_c = c9.pkcs7_pad(new_c)
    return c10.aes_128_cbc_encrypt(new_c, key, IV=key)

def verify_url(data):
    """
    Verifies that a URL is valid by decrypting the data, and checking all
    bytes are below 128 in value.

    Args:
        data: The encrypted URL

    Returns:
        True if the plaintext is valid, and the plaintext
    """
    pt    = c10.aes_128_cbc_decrypt(data, key, key)
    valid = True

    for c in pt:
        valid &= c < 128

    return valid, pt

def attack_cbc():
    """
    Breaks CBC mode when the IV is key, as described in the challenge.

    Returns:
        True if the attack worked
    """
    ct        = encrypt_userdata(b'blahblahblah')
    bad_ct    = ct[:16] + (b'\x00' * 16) + ct[:16]
    valid, pt = verify_url(bad_ct)
    k         = c2.xorstrs(c6.get_block(pt, 0), c6.get_block(pt, 2))
    return k == key

class Test27(unittest.TestCase):
    def test_challenge_27(self):
        self.assertTrue(attack_cbc())

if __name__ == "__main__" :
    unittest.main()

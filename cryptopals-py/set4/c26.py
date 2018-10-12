"""
Challenge 26
CTR Bitflipping

There are people in the world that believe that CTR resists bit flipping
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead
of CBC mode. Inject an 'admin=true' token.
"""
import sys, os, unittest
sys.path.insert(0, '../set3')
import c18


key    = os.urandom(16)
prefix = b'comment1=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

def encrypt_userdata(data):
    """
    Encrypts the given data under AES-128-CTR with a secret key, after
    appending and prepending data and quoting out metacharacters.

    Args:
        data: The user data to be encrypted

    Returns:
        AES-128-CBC(prefix || user-data || suffix, random-key)
    """
    new_c  = prefix + data.replace(b';', b'').replace(b'=', b'') + suffix
    return c18.aes_128_ctr(new_c, key)

def is_admin(cookie):
    """
    Decryption oracle. Decrypts the cookie and searches for the admin token.

    Args:
        cookie: The encrypted cookie containing the user data

    Returns:
        True if the cookie contains ';admin=true;'
    """
    data = c18.aes_128_ctr(cookie, key)
    return b';admin=true;' in data


# How does this differ from the CBC attack?
## PT ^ KEY = CT
## CT ^ KEY = PT
## PT ^ ATTACK = MY_PT
## CT ^ KEY ^ ATTACK = MY_PT
# So what should attack be?
# I think this is actually the same, except
# you don't attack the previous block. You just attack
# the block you want to change.
def ctr_attack():
    """
    Performs the CBC bitflipping attack on the oracle

    Returns:
        True if the attack is successful
    """
    data     = b'XadminXtrue'
    original = encrypt_userdata(data)
    cracked  = original[:32]
    cracked  += convert_char(original[32], 'X', ';')
    cracked  += original[33:38]
    cracked  += convert_char(original[38], 'X', '=')
    cracked  += original[39:]
    return is_admin(cracked)

def convert_char(orig, now, later):
    """
    XORs all the characters together so that the decryption will result
    in the character I want.

    Args:
        orig: Character from the ciphertext
        now: Character that the decryption would currently be (X)
        later: Character that we want to get

    Returns:
        The byte value that is the result of XORing all the given arguments,
        which will make the decryption result in the value needed.
    """
    return bytes([orig ^ ord(now) ^ ord(later)])

class TestCTRBitflip(unittest.TestCase):
    def test_challenge_26(self):
        self.assertTrue(ctr_attack())

if __name__ == '__main__' :
    unittest.main()

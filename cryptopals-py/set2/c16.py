"""
**Challenge 16**

*CBC Bitflipping Attacks*

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend
the string:

``'comment1=cooking%20MCs;userdata='``

...and append the string:

``';comment2=%20like%20a%20pound%20of%20bacon'``

The function should quote out the ';' and '=' characters.

The function should then pad out the input to the 16-byte AES block length
and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters
";admin=true;".

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to
provide user input to it that will generate the string the second function is
looking for. We'll have to break the crypto to do that.

Instead modify the ciphertext (without knowledge of the AES key) to accomplish
this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
block:
* Completely scrambles the block the error occurs in
* Produces the identical 1-bit error in the next ciphertext block
"""
import sys, os, unittest
sys.path.insert(0, '../set1')
import c10, c9, c6

key    = os.urandom(16)
prefix = b'comment1=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

def encrypt_userdata(data):
    """
    Encrypts the given data under AES-128-CBC with a secret key, after
    appending and prepending data and quoting out metacharacters.

    Args:
        data: The user data to be encrypted

    Returns:
        AES-128-CBC(prefix || user-data || suffix, random-key)
    """
    new_c  = prefix + data.replace(b';', b'').replace(b'=', b'') + suffix
    new_c = c9.pkcs7_pad(new_c)
    return c10.aes_128_cbc_encrypt(new_c, key)

def is_admin(cookie):
    """
    Decryption oracle. Decrypts the cookie and searches for the admin token.

    Args:
        cookie: The encrypted cookie containing the user data

    Returns:
        True if the cookie contains ';admin=true;'
    """
    data = c10.aes_128_cbc_decrypt(cookie, key)
    data = c9.pkcs7_unpad(data)
    return b';admin=true;' in data


### 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
### comment1=cooking %20MCs;userdata= XadminXtrueX

## So I should be able to send the above as my data
## and then send it in with the right bit flips to
## make the X's the characters I want.
def cbc_attack():
    """
    Performs the CBC bitflipping attack on the oracle

    Returns:
        True if the attack is successful
    """
    data     = b'XadminXtrueX'
    original = encrypt_userdata(data)
    cracked  = original[:16]
    cracked  += convert_char(original[16], 'X', ';')
    cracked  += original[17:22]
    cracked  += convert_char(original[22], 'X', '=')
    cracked  += original[23:27]
    cracked  += convert_char(original[27], 'X', ';')
    cracked  += original[28:]
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

class TestCBCBitflip(unittest.TestCase):
    def test_challenge_16(self):
        self.assertTrue(cbc_attack())

if __name__ == "__main__" :
    unittest.main()

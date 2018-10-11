"""
Challenge 5
Implement repeating-key XOR

Here is the opening stanza of an important work of the
English language:
  Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E,
then I again for the 4th byte, and so on.

It should come out to:
 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
 a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt
your mail. Encrypt your password file. Your .sig file. Get a feel for it.
I promise, we aren't wasting your time with this.
"""
import c1, c2, c3, c4
import unittest

# Extend a key to size n
def key_extend(key, n):
    """
    Extends a key to size n

    Args:
        key: The key to be extended
        n: The size to extend the key out to

    Returns:
        The key repeated as many times as needed to be of length n.
    """
    diff = n // len(key)
    if diff > 0:
        key = key * (diff+1)
    return key[0:n]

# Repeating key works the same so all we needed was the above function
def repeating_key_xor(txt, key):
    """
    Encrypts the given plain text under the given key after extending it.

    Args:
        txt: The plain text to be encrypted
        key: The key to encrypt under

    Returns:
        The ciphertext created by XORing the plaintext under the repeating key.
    """
    return c2.xorstrs(txt, key_extend(key, len(txt)))

class TestRepeatingKeyXOR(unittest.TestCase):
    def test_key_extend(self):
        self.assertEqual(key_extend(b'ICE', 6), b'ICEICE')
        self.assertEqual(key_extend(b'ICE', 5), b'ICEIC')
        self.assertEqual(key_extend(b'ICE', 15), b'ICEICEICEICEICE')

    def test_challenge_5(self):
        pt  = b'Burning \'em, if you ain\'t quick and nimble\n'
        pt  += b'I go crazy when I hear a cymbal'
        ct  = repeating_key_xor(pt, b'ICE')
        ans = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        ans += b'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        self.assertEqual(c1.asciitohex(ct), ans.upper())

if __name__ == '__main__' :
    unittest.main()

"""
Challenge 25
Break 'random access read/write' AES CTR

Back to CTR. Encrypt the recovered plaintext from this file under CTR with a
random key (unknown to you).

Now write the code that allows you to 'seek' into the ct, decrypt, and
re-encrypt with different pt. Expose this function as
    edit(ct, key, offset, newtext)

Imagine the edit function was exposed to attackers by means of an API call
that didn't reveal the key or the original plaintext; the attacker has the ct
and controls the offset and newtext.

Recover the original plaintext
"""
import os, sys, unittest
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
sys.path.insert(0, '../set3')
import c1, c2, c7, c18

key  = os.urandom(16)

def edit(ct, key, offset, newtext):
    """
    Seeks into ciphertext at an offset and re-encrypts with a different
    plaintext, using AES-128-CTR.

    Args:
        ct: The full ciphertext to seek into.
        key: The encryption key.
        offset: The byte offset to make the edit at.
        newtext: The new plaintext.

    Returns:
        The ciphertext re-encrypted with the new plaintext starting at offset.
    """
    new_ct = ct[:offset]
    new_ct += c18.aes_128_ctr((b'\x00' * offset) + newtext, key)[offset:]
    new_ct += ct[offset+len(newtext):]
    return new_ct

def api_edit(ct, offset, newtext):
    """
    API edit call that does not expose the key.

    Args:
        ct: The full ciphertext to seek into.
        offset: The byte offset to make the edit at.
        newtext: The new plaintext

    Returns:
        The ciphertext re-encrypted with the new plaintext starting at offset.
    """
    return edit(ct, key, offset, newtext)

class Test25(unittest.TestCase):
    def setUp(self):
        f = open('../../testdata/25.txt')
        self.ptxt = c1.base64toascii(f.read())
        self.ptxt = c7.aes_128_ecb_decrypt(self.ptxt, b'YELLOW SUBMARINE')
        f.close()
    def test_challenge_25(self):
        ctxt = c18.aes_128_ctr(self.ptxt, key)
        self.assertEqual(len(ctxt), len(api_edit(ctxt, 5, b'abcde')))
        pt = api_edit(ctxt, 0, ctxt)
        self.assertEqual(pt, self.ptxt)

if __name__ == '__main__' :
    unittest.main()

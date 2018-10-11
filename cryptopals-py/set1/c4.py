"""
Challenge 4
Detect single-character XOR

One of the 60-character strings in this file has been encrypted
by single-character XOR. Find it.
"""
import c1, c2, c3
import unittest

DEBUG = False

## It'll be a little slow but I think the best approach
## here will be running challenge3 on all 60 lines.
def detect_xor(file):
    """
    Finds the line that is encrypted with single byte XOR

    Args:
        file: The file to read lines from

    Returns:
        The pair containing the line from the file that was detected, and the
        decryption key for it.
    """
    best_score = 0
    best_key   = 0
    best_ct    = 0
    idx        = 0
    for line in file:
        idx += 1
        ct  = c1.hextoascii(line.strip())
        key = c3.single_byte_xor(ct)
        pt  = c2.xorstrs(ct, bytes([key]) * len(ct))
        scr = c3.score(pt)
        if DEBUG:
            print('Line: ' + str(idx))
            print('Key: ' + str(key))
            print('PT: ' + str(pt))
            print('Score: ' + str(scr))
        # Single byte XOR should return a key of 0 when the ciphertext is not
        # XOR encrypted. Thus we should be able to stop as soon as we get a key
        # that is not 0.
        if scr > 0:
            return ct, key
    raise RuntimeException('no suitable line found')

class TestDetectXOR(unittest.TestCase):
    def setUp(self):
        self.file = open('../../testdata/4.txt')
    def tearDown(self):
        self.file.close()
    def test_challenge_4(self):
        ct, key = detect_xor(self.file)
        pt = c2.xorstrs(ct, bytes([key]) * len(ct))
        self.assertEqual(key, 53)
        self.assertEqual(pt, b'Now that the party is jumping\n')

if __name__ == "__main__" :
    unittest.main()

"""
**Challenge 8**

*Detect AES in ECB Mode*

In this file are a bunch of hex-encoded ciphertexts. One of them
has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and
deterministic; the same 16-byte plaintext block will always produce
the same 16-byte ciphertext.
"""
import c1, c6
import unittest

## Well the easiest solution here is to
## see if any of the ciphertexts have repeated blocks.
## Turns out quite a few have repeated blocks, so the
## next best option is take the one with the most
## repeated blocks

# Determines if a given txt is encrypted
# with ECB. Takes an argument for the max number
# of repeated blocks to be considered too many.
def is_ecb(txt, maxBlocks=1):
    """
    Determines if a given ciphertext was encrypted in ECB mode looking for
    repeated blocks.

    Args:
        txt: The ciphertext in question
        maxBlocks: The maximum number of repeated blocks allowed before it is
        considered to be ECB.

    Returns:
        True if the txt was encrypted with ECB
    """
    num_blocks = len(txt) // 16
    maxCount   = 1
    for i in range(num_blocks):
        block = c6.get_block(txt, i, 16)
        count = txt.count(block)
        if count > maxCount:
            maxCount = count
    return maxCount > maxBlocks

class TestIsECB(unittest.TestCase):
    def setUp(self):
        self.f = open('../../testdata/8.txt')
    def tearDown(self):
        self.f.close()
    def test_challenge_8(self):
        linenum = 0
        result  = ''
        expected = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c74'
        expected += '4cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d'
        expected += '2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc0'
        expected += '6f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649'
        expected += 'af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040de'
        expected += 'b0ab51b29933f2c123c58386b06fba186a'

        for line in self.f.readlines():
            if is_ecb(c1.hextoascii(line.strip()), 3):
                result = line.strip()
                break
            linenum += 1
        self.assertEqual(linenum, 132)
        self.assertEqual(result, expected)

if __name__ == "__main__" :
    unittest.main()

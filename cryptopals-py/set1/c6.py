"""
Challenge 6
Break repeating-key XOR

There's a file here. It's been base64'd after being encrypted
with repeating-key XOR.

Decrypt it. Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

2. Write a function to compute the edit distance/Hamming distance between two
   strings. The Hamming distance is just the number of differing bits.
   The distance between:
      this is a test
   and
      wokka wokka!!!
   is 37. Make sure your code agrees before you proceed.

3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
   KEYSIZE worth of bytes, and find the edit distance between them.
   Normalize this result by dividing by KEYSIZE.

4. The KEYSIZE with the smallest normalized edit distance is probably the key.
   You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
   KEYSIZE blocks instead of 2 and average the distances.

5. Now that you probably know the KEYSIZE; break the ciphertext into blocks
   of KEYSIZE length.

6. Now transpose the blocks: make a block that is the first byte of every
   block, and a block that is the second byte of every block, and so on.

7. Solve each block as if it was single-character XOR. You already have code to
   do this.

8. For each block, the single-byte XOR key that produces the best looking
   histogram is the repeating-key XOR key byte for that block. Put them together
   and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key XOR ('Vigenere') statistically is obviously an academic exercise,
a "Crypto 101" thing. But more people "know how" to break it than can actually
break it, and a similar technique breaks something much more important.
"""
import c1, c2, c3, c4, c5
import unittest

## The challenge tells you in good detail
## how to do it. It's just a matter of implementing it.
maxKeysize = 40

def hamming_dist(str1, str2):
    """
    Calculates the Hamming distance between two bytestrings.

    Args:
        str1: The first bytestring
        str2: The second bytestring

    Returns:
        The hamming distance between the two given strings
    """
    # XOR each character, convert to binary representation,
    # and count the 1's. This gives you the differing bits.
    xord = c1.asciitohex(c2.xorstrs(str1, str2))
    return bin(int(xord, base=16)).count('1')


def edit_distance(keysize, txt):
    """
    Calculates the edit distance for a keysize-sized block from the text

    Args:
        keysize: The keysize to get the edit distance for
        txt: The text to split into blocks

    Returns:
        The average hamming distance between the blocks of text.
    """
    ## Let's get the average hamming distance for as
    ## many blocks as we can get.
    rounds = len(txt) // keysize - 1
    total  = 0.0
    for i in range(rounds):
        str1  = get_block(txt, i, keysize)
        str2  = get_block(txt, i+1, keysize)
        total += hamming_dist(str1, str2)
    return (total / rounds) / keysize

# Get the n'th block of size size from txt
def get_block(txt, n, size=16):
    """
    Gets the n'th block of txt.

    Args:
        txt: The text to extract a block from
        n: The 0-indexed block number
        size: The block size
    """
    return txt[size*n : size*(n+1)]

def guess_keysize(txt):
    """
    Guesses the keysize of the given ciphertext by taking the keysize with the
    smallest normalized edit distance.

    Args:
        txt: The ciphertext to get the keysize for

    Returns:
        The most likely keysize for the text.
    """
    # Using maxKeysize, create a dictionary of
    # entries [keysize, avg_hamming_dist]
    key_dists = dict.fromkeys(range(2, maxKeysize))
    ## Loop through every keysize and get their average
    ## hamming distances
    for i in range(2, maxKeysize):
        key_dists[i] = edit_distance(i, txt)
    return min(key_dists, key=key_dists.get)

def split_ct(txt, size):
    """
    Splits the ciphertext into blocks of the given size.

    Args:
        txt: The ciphertext to be split
        size: The size of each block

    Returns:
        A list of blocks of size [size] created from the ciphertext. The last
        element may be smaller than [size].
    """
    blocks = [b''] * size
    for i in range(0, len(txt)):
        blocks[i%size] += bytes([txt[i]])
    return blocks

def solve_blocks(blocks):
    """
    Solves each block of ciphertext as a single byte XOR cipher.

    Args:
        blocks: The blocks of ciphertext, split up and transposed as described
        in step 6.

    Returns:
        The key for the ciphertext
    """
    key   = b''
    for chunk in blocks:
        nkey = c3.single_byte_xor(chunk)
        key   += bytes([nkey])
    return key

class TestVigenereBreak(unittest.TestCase):
    def setUp(self):
        f = open('../../testdata/6.txt')
        self.ctxt = c1.base64toascii(f.read())
        f.close()
    def test_challenge_6(self):
        keysize = guess_keysize(self.ctxt)
        self.assertEqual(keysize, 29)
        blocks  = split_ct(self.ctxt, keysize)
        key     = solve_blocks(blocks)
        self.assertEqual(key, b'Terminator X: Bring the noise')
        # If curious, uncomment the following line
        #print(c5.repeating_key_xor(self.ctxt, key))

if __name__ == '__main__' :
    unittest.main()

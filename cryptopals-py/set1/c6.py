# Challenge 6
## Break repeating-key XOR
import c1
import c2
import c3
import c4
import c5

## The challenge tells you in good detail 
## how to do it. It's just a matter of implementing it.

## 1. Let KEYSIZE be the guessed length of the key; 
## try values from 2 to (say) 40.
maxKeysize = 40

## 2. Write a function to compute the edit distance/Hamming
## distance between two strings.
def hamming_dist(str1, str2):
    count = 0
    # Strings must be equal length
    assert (len(str1) == len(str2)), '\nstrings not == len\n' + str1 + '\n' + str2
    # XOR each character, convert to binary representation,
    # and count the 1's. This gives you the differing bits.
    for (chr1, chr2) in zip(str1, str2):
        count += bin(ord(chr1) ^ ord(chr2)).count('1')
    return count

## 3. For each KEYSIZE, take the first KEYSIZE worth
## of bytes, and the second KEYSIZE worth of bytes, and
## find the edit distance between them. Normalize this result
## by dividing by KEYSIZE.
def edit_distance(keysize, txt):
    ## Let's get the average hamming distance for as
    ## many blocks as we can get.
    rounds = (len(txt) / keysize) - 1
    total = 0.0
    for i in range(rounds):
        str1 = get_block(txt, i, keysize)
        str2 = get_block(txt, i+1, keysize)
        total += hamming_dist(str1, str2)
    return (total / rounds) / keysize

# Get the n'th block of size size from txt
def get_block(txt, n, size):
    return txt[size*n : size*(n+1)]

## 4. The KEYSIZE with the smallest normalized edit
## distance is probably the key.
def guess_keysize(txt):
    # Using maxKeysize, create a dictionary of
    # entries [keysize, avg_hamming_dist]
    key_dists = dict.fromkeys(range(1, maxKeysize))
    ## Loop through every keysize and get their average
    ## hamming distances
    for i in range(1, maxKeysize):
        key_dists[i] = edit_distance(i, txt)
    #return sorted(key_dists, key=key_dists.get)
    return min(key_dists, key=key_dists.get)

## 5. Now that you probably know the KEYSIZE; break the ciphertext
## into blocks of KEYSIZE length.
## 6. Now transpose the blocks: make a block that is the first byte
## of every block, and a block that is the second byte of every block,
## and so on.
def split_ct(txt, keysize):
    blocks = [''] * keysize
    for i in range(0, len(txt)):
        blocks[i%keysize] += txt[i]
    return blocks


## 7. Solve each block as if it was single-character XOR.
def solve_blocks(blocks):
    key = ''
    guess = ''
    for chunk in blocks:
        nkey, nguess = c3.single_byte_xor(chunk)
        if nkey is None:
            return 0, ''
        key += chr(int(nkey))
        guess += nguess
    return key, guess

## Challenge 6 solution
def main():
    # Open the file and decode from base64
    f = open('../../testdata/6.txt')
    ctxt = f.read()
    ctxt = ctxt.decode('base64')
    # Get the most likely keysize
    keysize = guess_keysize(ctxt)
    # Split ct into keysize chunks
    blocks = split_ct(ctxt, keysize)
    # Solve the blocks
    key, guess = solve_blocks(blocks)
    assert key == 'Terminator X: Bring the noise'

if __name__ == '__main__' : main()

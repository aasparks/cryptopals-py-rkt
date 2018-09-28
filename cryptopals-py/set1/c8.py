# Challenge 8
## Detect AES in ECB mode
import c6

### In this file are a bunch of hex-encoded ciphertexts. One of them
### has been encrypted with ECB.
### Detect it.
### Remember that the problem with ECB is that it is stateless and
### deterministic; the same 16-byte plaintext block will always produce
### the same 16-byte ciphertext.

## Well the easiest solution here is to
## see if any of the ciphertexts have repeated blocks.
## Turns out quite a few have repeated blocks, so the
## next best option is take the one with the most
## repeated blocks

# Determines if a given txt is encrypted
# with ECB. Takes an argument for the max number
# of repeated blocks to be considered too many.
def is_ecb(txt, maxBlocks=1):
    num_blocks = len(txt) / 4
    maxCount   = 1
    for i in range(num_blocks):
        block = c6.get_block(txt, i, 4)
        count = txt.count(block)
        if count > maxCount:
            maxCount = count
    return maxCount > maxBlocks

# Solves challenge 8.
# Checks each line and takes the one
# with the most repeated blocks
def challenge8():
    f        = open('../../testdata/8.txt')
    linenum  = 0
    result   = ''
    expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc"
    expected += "06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0"
    expected += "348542bb5708649af70dc06f4fd5d2d69c744cd2839"
    expected += "475c9dfdbc1d46597949d9c7e82bf5a08649af70dc0"
    expected += "6f4fd5d2d69c744cd28397a93eab8d6aecd56648915"
    expected += "4789a6b0308649af70dc06f4fd5d2d69c744cd283d4"
    expected += "03180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c"
    expected += "123c58386b06fba186a"
    for l in f.readlines():
        if is_ecb(l, 3):
            result = l.strip()
            break
        linenum += 1
    assert linenum == 132
    assert result  == expected, '\n' + result + '\n' + expected


if __name__ == "__main__" : challenge8()

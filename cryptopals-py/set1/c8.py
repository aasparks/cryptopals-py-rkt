# Challenge 8
## Detect AES in ECB mode
import c6
### Well the easiest solution here is to
### see if any of the ciphertexts have repeated blocks.
### Turns out quite a few have repeated blocks, so the
### next best option is take the one with the most 
### repeated blocks

# Determines if a given txt is encrypted 
# with ECB. Takes an argument for the max number
# of repeated blocks to be considered too many.
def is_ecb(txt, maxBlocks=1):
    num_blocks = len(txt) / 4
    maxCount = 1
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
    f = open('../../testdata/8.txt')
    linenum = 0
    total = 0
    for l in f.readlines():
        ecb = is_ecb(l, 3)
        if ecb:
            print 'ECB found on line ' + str(linenum)
            print l
        linenum += 1
    print 'done'


if __name__ == "__main__" : challenge8()

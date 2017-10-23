# Challenge 8
## Detect AES in ECB mode
import c1, c2, c3, c4, c5, c6, c7
### Well the easiest solution here is to
### see if any of the ciphertexts have repeated blocks.
### Turns out quite a few have repeated blocks, so the
### next best option is take the one with the most 
### repeated blocks

# Returns the number of repeated blocks.
# Calling function uses a max value to decide
# if the text has too many repeated blocks.
def is_ecb(txt):
    num_blocks = len(txt) / 4
    maxCount = 1
    for i in range(num_blocks):
        block = c6.get_block(txt, i, 4)
        count = txt.count(block)
        if count > maxCount:
            maxCount = count
    return maxCount

# Solves challenge 8.
# Checks each line and takes the one
# with the most repeated blocks
def challenge8():
    f = open('8.txt')
    linenum = 0
    total = 0
    for l in f.readlines():
        ecb = is_ecb(l)
        if ecb > 3:
            print 'ECB found on line ' + str(linenum)
            print l
        linenum += 1
    print 'done'


if __name__ == "__main__" : challenge8()

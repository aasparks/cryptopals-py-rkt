# Challenge 4
## Detect single-character XOR
import c1
import c2
import c3
### It'll be a little slow but I think the best approach
### here will be running challenge3 on all 60 lines.
def main():
    f = open("../../testdata/4.txt")
    bestScore = 0
    bestGuess = ''
    bestKey   = ''
    for line in f:
        ct = c1.hextoascii(line.strip())
        aKey, aGuess = c3.single_byte_xor(ct)
        aScore = c3.score(aGuess)
        if aScore > bestScore:
            bestScore = aScore
            bestGuess = aGuess
            bestKey = aKey
    assert bestGuess == 'Now that the party is jumping\n'

if __name__ == "__main__" : main()

# Challenge 3
## Single-byte XOR cipher
import c1
import c2
import string
import re
### I need to write a function to score a piece of plaintext as
### English or not. A simple frequency analysis should work.

## First let's get a dictionary of the relative character frequency for English.
knownfreq = {'a' : 0.082, 'b' : 0.015, 'c' : 0.028, 'd' : 0.043, 'e' : 0.0127,
                          'f' : 0.022, 'g' : 0.020, 'h' : 0.061, 'i' : 0.069, 'j' : 0.002,
                          'k' : 0.008, 'l' : 0.040, 'm' : 0.024, 'n' : 0.067, 'o' : 0.075,
                          'p' : 0.019, 'q' : 0.001, 'r' : 0.059, 's' : 0.063, 't' : 0.091,
                          'u' : 0.028, "v" : 0.009, 'w' : 0.024, 'x' : 0.002, 'y' : 0.019,
                          'z' : 0.001}

# Score a string. High score is more likely English
def score(txt):
    # First we can assume strings in English only contain
    # the alphabet, numbers, and some symbols. This let's us
    # throw out bad strings immediately
    bad_chars = set('~@#$%^&*/=+\|<>')
    # Go through the string and check each character
    for c in txt.strip():
        # If it's less than ascii 32 (except for '\n')
        # we can assume it is definitely not English.
        if ord(c) < 32 and ord(c) != ord('\n'):
            return 0
        # If it's one of the bad_chars, we can assume
        # it's not English.
        if c in bad_chars:
            return 0
    freq = dict.fromkeys(string.ascii_lowercase, 0)
    # Get only the letters from the string. All other characters
    # should be valid at this point.
    ntxt = re.sub('[^a-z]+', '', txt.lower())
    # If we don't have any, it isn't English
    if len(ntxt) == 0:
        return 0
    # Now get the frequency of each character
    for c in ntxt:
        freq[c] += 1
    for c in string.ascii_lowercase:
        freq[c] = freq[c] / (len(txt) + 0.0)
    return score_freqs(freq)

# Assign a score based on relative frequency
def score_freqs(freq):
    idx = 0
    scr = 0
    # Go through the alphabet in order of most frequent
    for key in 'etaionshrdlcumvfgypbvkjxqz':
        # This part here is totally arbitrary. I played around with numbers
        # and found this to be most effective. 
        if abs(knownfreq[key] - freq[key]) < (knownfreq[key] / 2.0):
            if idx < 8:
                scr += 1
            elif idx < 19:
                scr += 0.5
            else:
                scr += 0.25
        else:
            if idx < 8:
                scr -= 1
            elif idx < 19:
                scr += 0.5
            else:
                scr += 0.25
        idx += 1
    return scr


# Now that I can score, I have to find out what the key is
def single_byte_xor(txt):
    ## I have no choice but to try every key. This is okay
    ## since there are so few keys.
    maxScore = -3
    bestGuess = ''
    bestKey = 0
    for x in range(1, 255):
        # Score every attepmt and take the highest score
        attempt = c2.xorstrs(txt, chr(x) * len(txt))
        scr = score(attempt)
        if scr > maxScore:
            maxScore = scr
            bestKey = str(x)
            bestGuess = attempt
    return bestKey, bestGuess

# Solution to Challenge 3
def main():
    txt = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    txt = c1.hextoascii(txt)
    key, guess = single_byte_xor(txt)
    assert key == '88'
    assert guess == 'Cooking MC\'s like a pound of bacon'
    print 'pass'
    #print 'Key: ' + str(key)
    #print 'Best guess: '
    #print guess

if __name__ ==  "__main__" : main()

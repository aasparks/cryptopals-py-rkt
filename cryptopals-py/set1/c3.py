"""
**Challenge 3**

*Single-byte XOR cipher*

The hex encoded string:

``1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736``

...has been XOR'd against a single character. Find the key,
decrypt the message.

You can do this by hand. But don't: write code to do it for you.
How? Devise some method for 'scoring' a piece of English plaintext.
Character frequency is a good metric. Evaluate each output and choose
the one with the best score.
"""
import c1, c2
import string, re, unittest

## I need to write a function to score a piece of plaintext as
## English or not. A simple frequency analysis should work.
## First let's get a dictionary of the relative character frequency for English.
knownfreq = {'a' : 0.082, 'b' : 0.015, 'c' : 0.028, 'd' : 0.043, 'e' : 0.0127,
             'f' : 0.022, 'g' : 0.020, 'h' : 0.061, 'i' : 0.069, 'j' : 0.002,
             'k' : 0.008, 'l' : 0.040, 'm' : 0.024, 'n' : 0.067, 'o' : 0.075,
             'p' : 0.019, 'q' : 0.001, 'r' : 0.059, 's' : 0.063, 't' : 0.091,
             'u' : 0.028, "v" : 0.009, 'w' : 0.024, 'x' : 0.002, 'y' : 0.019,
             'z' : 0.001}
DEBUG = False

# Score a string. High score is more likely English
def score(txt):
    """
    Scores a piece of text on how likely it is to be English, using
    frequency analysis.

    Args:
        txt: The bytestring to be analyzed for frequency of English characters

    Returns:
        A score in the range of 0 to 26 for the likelihood of being English
    """
    # First we can assume strings in English only contain
    # the alphabet, numbers, and some symbols. This let's us
    # throw out bad strings immediately
    bad_chars = set(b'~@#$%^&*=+|\/<>')
    # Go through the string and check each character for disqualification
    for c in txt:
        # If it's less than ascii 32 (except for '\n')
        # we can assume it is definitely not English.
        is_bad_char = c < 32 and c != ord('\n')
        # If it's greater than 127, it is also invalid
        is_bad_char |= c > 127
        is_bad_char |= c in bad_chars
        if is_bad_char:
            if DEBUG:
                print('got bad char ' + str(c))
            return 0

    # Get the frequency of each [a-z] character in the string
    freq = dict.fromkeys(string.ascii_lowercase, 0)
    ntxt = re.sub('[^a-z]+', '', str(txt.lower()))
    # If there are no [a-z] chars, it isn't English
    if len(ntxt) == 0:
        return 0

    # Now get the frequency of each character
    for c in ntxt:
        freq[c] += 1
    for c in string.ascii_lowercase:
        freq[c] = freq[c] / len(txt)
    return __score_freqs(freq)

# Assign a score based on relative frequency
def __score_freqs(freq):
    """
    Assigns a score given the relative frequency of each character.

    Args:
        freq: A dictionary containing each character [a-z] and the associated
        relative frequency for that character.

    Returns:
        The value that determines how close to the English language a piece
        of text is.
    """
    scr = 0
    # Go through the alphabet in order of most frequent
    for key in 'etaionshrdlcumvfgypbvkjxqz':
        # This part here is totally arbitrary. I played around with numbers
        # and found this to be most effective. Basically, if the freq is
        # within half the known, it is considered good
        if abs(knownfreq[key] - freq[key]) < (knownfreq[key] / 2):
            scr += 1
    return scr


# Now that I can score, I have to find out what the key is
def single_byte_xor(txt):
    """
    Solves the single byte XOR cipher by trying every possible key value
    and scoring the resulting plaintext for its similarity to the English
    language.

    Args:
        txt: The ciphertext to be deciphered.

    Returns:
        The key with the highest score.
    """
    maxScore  = -3
    bestKey   = 0
    for x in range(256):
        # Score every attempt and take the highest score
        attempt = c2.xorstrs(txt, bytes([x]) * len(txt))
        scr     = score(attempt)

        if DEBUG:
            print(str(x) + ': ' + str(scr))

        if scr > maxScore:
            maxScore  = scr
            bestKey   = x
    return bestKey

class TestSingleXOR(unittest.TestCase):
    def setUp(self):
        self.ctxt = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        self.ctxt = c1.hextoascii(self.ctxt)

    def test_challenge_3(self):
        actual_key   = single_byte_xor(self.ctxt)
        expected_key = 88
        actual_txt   = c2.xorstrs(self.ctxt, bytes([actual_key])*len(self.ctxt))
        expected_txt = b'Cooking MC\'s like a pound of bacon'
        self.assertEqual(actual_key, expected_key)
        self.assertEqual(actual_txt, expected_txt)

if __name__ ==  "__main__" :
    unittest.main()

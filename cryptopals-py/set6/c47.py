"""
**Challenge 47**

*Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)*

Let us Google this for you: "Chosen ciphertext attacks against protocols based
on the RSA encryption standard."

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on the
first search page.

Read the paper. It describes a padding oracle attack on PKCS#1v1.5. The attack
is similar in spirit to the CBC padding oracle you built earlier; it's an
"adaptive chosen ciphertext attack", which means you start with a valid
ciphertext and repeatedly corrupt it, bouncing the adulterated ciphertexts off
the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 9th
grade math, but also has you implementing an algorithm that is complex on par
with finding a minimum cost spanning tree.

The setup:
    * Build an oracle function, just like you did in the last exercise, but have
      it check for plaintext[0] == 0 and plaintext[1] == 2.
    * Generate a 256 bit keypair (this is, p and q will each be 128 bit primes),
      [n, e, d].
    * Plug d and n into your oracle function.
    * PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt
      it to get "c".
    * Decrypt "c" using your padding oracle.

For this challenge, we've used an untenably small RSA modulus (you could factor
this keypair instantly). That's because this exercise targets a specific step in
the Bleichenbacher paper --- Step 2c, which implements a fast, nearly O(log n)
search for the plaintext.

Things you want to keep in mind as you read the paper:
    * RSA ciphertexts are just numbers.
    * RSA is "homomorphic" with respect to multiplication, which means you can
      multiply c * RSA(2) to get a c' that will decrypt to plaintext * 2. This
      is mindbending but easy to see if you play with it in code -- try
      multiplying ciphertexts with the RSA encryptions of numbers so you know
      you grok it.
    * What you need to grok for this challenge is that Bleichenbacher uses
      multiplication on ciphertexts the way the CBC oracle uses XORs of random
      blocks.
    * A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a
      number between 02:00:00...00 and 02:FF:FF...FF --- in other words, 2B and
      3B - 1, where B is the bit size of the modulus minus the first 16 bits.
      When you see 2B and 3B, that's the idea the paper is playing with.

    To decrypt "c", you'll need step 2a from the paper (the search for the
    first "s" that, when encrypted and multiplied with the ciphertext, produces
    a conformant plaintext), Step 2c, the fast O(log n) search, and Step 3.

    Your Step 3 code is probably not going to need to handle multiple ranges.

    We recommend you just use the raw math from the paper (check, check, double
    check your translation to code) and not spend too much time trying to grok
    how the math works.
"""
import os, sys, unittest
sys.path.insert(0, '../set5')
import c39
from Crypto.Util import number
import random

G_PRIV = 0,0
DEBUG = False

def attack_rsa(ctxt, pub):
    """
    Performs the full Bleichenbacher attack on PKCS1.5

    Args:
        ctxt (long): The ciphertext
        pub (long, long): The RSA public key in the form (e,n)
    Returns:
        The decoded message, with padding
    """
    e, n = pub
    k    = ceil(n.bit_length(), 8)
    B    = 2 ** (8 * (k - 2))
    c0   = ctxt
    M    = [(2 * B, 3 * B - 1)]
    i    = 1
    c, s = 0, 0

    # step1 is optional, and not happening in our example
    if not padding_oracle(c0):
        c0, s = step1(c0, pub)

    while True:
        # Step 2a
        if i == 1:
            c, s = step2a(c0, pub, B)
        # Step 2b
        elif len(M) >= 2:
            c, s = step2b(c0, pub, s)
        # Step 2c
        elif len(M) == 1:
            # check for solution here
            a, b = M[0]
            if a == b:
                return b'\x00' + number.long_to_bytes(a)
            # step 2c
            c, s = step2c(c0, pub, B, a, b, s)
        # Step 3
        M = step3(M, pub, B, s)
        if DEBUG:
            print(M)
        i += 1

def step1(c0, pub):
    """
    Performs Step 1 of the attack: blinding.

    Args:
        c (long): The ciphertext
        pub (long, long): The RSA public key in the form (e,n)

    Returns:
        c0, s
    """
    if DEBUG:
        print("Running Step 1")
    e, n = pub
    while True:
        s = random.randint(0, n-1)
        c = (c0 * pow(s, e, n)) % n
        if padding_oracle(c0):
            return c, s

def step2a(c0, pub, B):
    """
    Performs Step 2a of the attack: starting the search.

    Args:
        c0 (long): The ciphertext
        pub (long, long): The RSA public key in the form (e,n)
        B (long): The B value = 2**(8*(k-2))
    Returns
        c, s
    """
    if DEBUG:
        print('Running Step 2a')
    e, n  = pub
    s = ceil(n, 3*B)
    while True:
        c = (c0 * pow(s, e, n)) % n
        if padding_oracle(c):
            return c, s
        s += 1

def step2b(c0, pub, s):
    """
    Performs Step 2b of the attack: searching with 2+ intervals

    Args:
        c0 (long): The ciphertext
        pub (long, long): The RSA public key in the form (e,n)
        s (long): The current s value
    Returns
        c, s
    """
    if DEBUG:
        print("Running Step 2b")
    e, n = pub
    while True:
        s += 1
        c = (c0 * pow(s, e, n)) % n
        if padding_oracle(c):
            return c,s

def step2c(c0, pub, B, a, b, s):
    """
    Performs Step 2c of the attack: searching with 1 interval

    Args:
        c0
    Returns
        c, s
    """
    if DEBUG:
        print("Running Step 2c")
    e, n = pub
    r = ceil(2 * (b * s - 2 * B), n)

    while True:
        s_min = ceil(2*B + r*n, b)
        s_max = ceil(3*B + r*n, a)
        for s in range(s_min, s_max):
            c = (c0 * pow(s, e, n)) % n
            if padding_oracle(c):
                return c, s
        r += 1

def step3(M, pub, B, s):
    """
    Performs Step 3 of the attack: Narrowing solution set

    Args:
        M: Solution set search ranges
        pub (long, long): The RSA public key in the form (e,n)
        B (long): The B value = 2**(8*(k-2))
        s (long): The current s value
    Returns:
        M containing new, narrowed search ranges
    """
    if DEBUG:
        print('Running Step 3')
    e, n = pub
    M_n  = []
    for a,b in M:
        r_min = ceil(a*s - 3*B + 1, n)
        r_max = (b*s - 2*B) // n
        for r in range(r_min, r_max+1):
            l = max(a, ceil(2*B + r*n, s))
            u = min(b, (3*B - 1 + r*n) // s)
            if l > u:
                raise Exception('l > u')
            append_and_merge(M_n, l, u)
    if len(M_n) == 0:
        raise Exception('no search intervals')
    return M_n


def append_and_merge(intervals, lower, upper):
    """
    This function courtesy of GitHub user ricpacca at
    https://github.com/ricpacca/cryptopals
    Thanks, bro!

    Adds a new interval to the list of intervals.
    In particular:
    If there is no interval overlapping with the given boundaries,
    it just appends the new interval to the list.
    If there is already an interval overlapping with the given boundaries,
    it merges the two intervals together.
    """
    for i, (a, b) in enumerate(intervals):
        if not (b < lower or a > upper):
            a = min(lower, a)
            b = max(upper, b)
            intervals[i] = a, b
            return
    intervals.append((lower, upper))


def pkcs15_pad(msg, n):
    """
    Pads the given message according to PKCS1.5

    Args:
        msg: The message to pad
        key: The RSA public key value, n

    Returns:
        The PKCS1.5 padded message
    """
    k = ceil(n.bit_length(), 8)
    padd = os.urandom(k - 3 - len(msg))
    # make sure random data is non-zero
    for i in range(len(padd)):
        if padd[i] == b'\x00':
            padd[i] = random.randint(1, 256)
    return b'\x00\x02' + padd + b'\x00' + msg


def padding_oracle(ctxt):
    """
    Padding oracle. Decrypts the ciphertext and determines if it is
    PKCS1.5 complaint.

    Args:
        ctxt: The ciphertext
        priv: The RSA private key

    Returns:
        True if the plaintext is PKCS1.5 complaint.
    """
    priv = G_PRIV
    d, n = priv
    ctxt = number.long_to_bytes(ctxt)
    ptxt = c39.rsa_decrypt(ctxt, priv)
    # Weird issue with the leading \x00 being dropped by
    # number.long_to_bytes so we'll add it back if the length
    # is not k
    k = ceil(n.bit_length(), 8)
    if len(ptxt) < k:
        ptxt = b'\x00' * (k - len(ptxt)) + ptxt
    return ptxt[0] == 0 and ptxt[1] == 2

def ceil(a, b):
    """
    Quick and clean ceiling function. I'm using this because
    math.ceil() is waaaay slower for some reason and
    requires converting to a float (apparently?).

    Args:
        a (long): Dividend
        b (long): Divisor
    Returns:
        The ceiling of a/b
    """
    return (a + b - 1) // b

class TestChallenge47(unittest.TestCase):
    def setUp(self):
        global G_PRIV
        pub, priv = c39.rsa_keygen(bit_len=128)
        self.pub  = pub
        self.priv = priv
        G_PRIV    = priv
        self.msg  = b'kick it, CC'

    def test_rsa(self):
        ctxt = c39.rsa_encrypt(self.msg, self.pub)
        ptxt = c39.rsa_decrypt(ctxt, self.priv)
        self.assertEqual(self.msg, ptxt)

    def test_pad(self):
        e, n = self.pub
        padd = pkcs15_pad(self.msg, n)
        ctxt = c39.rsa_encrypt(padd, self.pub)
        self.assertTrue(padding_oracle(number.bytes_to_long(ctxt)))

    def test_attack(self):
        e, n    = self.pub
        padd    = pkcs15_pad(self.msg, n)
        ctxt    = c39.rsa_encrypt(padd, self.pub)
        decoded = attack_rsa(number.bytes_to_long(ctxt), self.pub)
        self.assertEqual(decoded, padd)


if __name__ == "__main__":
    unittest.main()

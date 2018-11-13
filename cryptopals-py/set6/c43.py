"""
**Challenge 43**

*DSA Key Recovery from Nonce*

Step 1: Relocate so that you are out of easy travel distance of us.

Step 2: Implement DSA, up to signing and verifying, including parameter
generation.

*Hah-hah you're too far away to come punch us.*

Just kidding. You can skip the parameter generation part if you want; if you do,
use these params::

    p = 800000000000000089e1855218a0e7dac38136ffafa72eda7
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
        1a584471bb1
    q = f4f47f05794b256174bba6e9b396a7707e563c5b
    g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba
        9fc95302291

("But I want smaller params!" Then generate them yourself.)

The DSA signing operation generates a random subkey "k". You know this because
you implemented the DSA sign operation.

This is the first and easier of two challenges regarding the DSA "k" subkey.

Given a known "k", it's trivial to recover the DSA private key "x"::

        (s * k) - H(msg)
    x = ---------------- mod q
                r

Do this a couple of times to prove to yourself that you grok it Capture it in a
function of some sort.

Now then. I used the parameters above. I generated a keypair. My pubkey is::

     y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
         abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
         e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
         1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
         bb283e6633451e535c45513b2d33c99ea17

I signed::

    For those that envy a MC it can be hazardous to your health
    So be friendly, a matter of life and death, just like a etch-a-sketch

(My SHA1 for this string was *d2d0714f014a9784047eaeccf956520045c45265*; I don't
know what NIST want you to do, but when I convert that hash to an integer I get:
*0xd2d0714f014a9784047eaeccf956520045c45265*)

I get::

    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

I signed this string with a broken implementation of DSA that generated "k"
values between 0 and 2^16. What's my private key?

Its SHA-1 fingerprint (after being converted to hex) is::

    0954edd5e0afe5542a4adf012611a91912a3ec16

Obviously, it also generates the same signature for that string.
"""
import random, unittest, sys
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set5')
import c1, c39
from hashlib import sha1
from Crypto.Util import number

def dsa_sign_with_k(message, params, key, k=0):
    """
    DSA signing operation which captures and returns k.

    Args:
        message: The message to sign for.
        params: DSA domain parameters as a triplet (p,q,g)
        key: The DSA private key (x)
        k: An optional k value for testing

    Returns:
        The DSA signature pair (r,s,k)
    """
    p,q,g = params
    n     = len(number.long_to_bytes(q))
    x     = key
    if k == 0:
        k = random.randrange(1, q)
    r = pow(g, k, p) % q
    #if r == 0:
    #    dsa_sign(message, params, key)
    h  = number.bytes_to_long(sha1(message).digest()[:n])
    xr = x * r
    s  = (c39.invmod(k,q) * (h + xr)) % q
    #if s == 0:
    #    dsa_sign(message, params, key)
    return r,s,k

def dsa_sign(message, params, key):
    """
    DSA signing operation.

    Args:
        message: The message to sign for.
        params: DSA domain parameters as a triplet (p,q,g)
        key: The DSA public key (y)

    Returns:
        The DSA signature pair (r,s)
    """
    r, s, k = dsa_sign_with_k(message, params, key)
    return r,s

def dsa_verify(message, signature, params, key):
    """
    DSA signature verification.

    Args:
        message: The message.
        signature: The signature for the message.
        params: The DSA domain parameters as a triplet (p,q,g)
        key: The DSA public key (y)

    Returns:
        True if signature validates
    """
    p,q,g = params
    y     = key
    r,s   = signature
    if r >= q or s >= q:
        print('Fuck up')
        return False
    w  = c39.invmod(s,q) % q
    H  = number.bytes_to_long(sha1(message).digest())
    u1 = (H * w) % q
    u2 = (r * w) % q
    v  = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

def get_x_from_k(message, signature, params, k):
    """
    Extracts the private key from the k value.

    Args:
        message: The message
        signature: The signature pair (r,s)
        params: DSA domain params (p,q,g)
        k: The k value used for the signature
    """
    r,s   = signature
    p,q,g = params
    sk    = (s * k)
    h     = number.bytes_to_long(sha1(message).digest())
    x     = ((sk - h) * c39.invmod(r,q)) % q
    return x

def brute_force_k(message, signature, params, y):
    r,s   = signature
    p,q,g = params
    for k in range(2**16):
        x = get_x_from_k(message, signature, params, k)
        if y == pow(g,x,p):
            return k,x
    raise ValueError('Key not found')

class TestChallenge43(unittest.TestCase):
    def setUp(self):
        p = b'800000000000000089e1855218a0e7dac38136ffafa72eda7'
        p += b'859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
        p += b'2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
        p += b'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
        p += b'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
        p += b'1a584471bb1'
        p = number.bytes_to_long(c1.hextoascii(p))

        q = b'f4f47f05794b256174bba6e9b396a7707e563c5b'
        q = number.bytes_to_long(c1.hextoascii(q))

        g = b'5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
        g += b'458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
        g += b'322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
        g += b'0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
        g += b'878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
        g += b'9fc95302291'
        g = number.bytes_to_long(c1.hextoascii(g))

        y =  b'084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        y += b'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        y += b'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        y += b'1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        y += b'bb283e6633451e535c45513b2d33c99ea17'

        self.params = p,q,g
        self.pub = number.bytes_to_long(c1.hextoascii(y))

    def test_dsa(self):
        p = b'a8f9cd201e5e35d892f85f80e4db2599a5676a3b'
        p += b'1d4f190330ed3256b26d0e80a0e49a8fffaaad2'
        p += b'a24f472d2573241d4d6d6c7480c80b4c67bb447'
        p += b'9c15ada7ea8424d2502fa01472e760241713dab'
        p += b'025ae1b02e1703a1435f62ddf4ee4c1b664066e'
        p += b'b22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5'
        p += b'b06439ac9c7e9d8bde283'
        p = number.bytes_to_long(c1.hextoascii(p))
        q = b'f85f0f83ac4df7ea0cdf8f469bfeeaea14156495'
        q = number.bytes_to_long(c1.hextoascii(q))
        g = b'2b3152ff6c62f14622b8f48e59f8af46883b38e7'
        g += b'9b8c74deeae9df131f8b856e3ad6c8455dab87c'
        g += b'c0da8ac973417ce4f7878557d6cdf40b35b4a0c'
        g += b'a3eb310c6a95d68ce284ad4e25ea28591611ee0'
        g += b'8b8444bd64b25f3f7c572410ddfb39cc728b9c9'
        g += b'36f85f419129869929cdb909a6a3a99bbe08921'
        g += b'6368171bd0ba81de4fe33'
        g = number.bytes_to_long(c1.hextoascii(g))
        msg = b'3b46736d559bd4e0c2c1b2553a33ad3c6cf23c'
        msg += b'ac998d3d0c0e8fa4b19bca06f2f386db2dcff'
        msg += b'9dca4f40ad8f561ffc308b46c5f31a7735b5f'
        msg += b'a7e0f9e6cb512e63d7eea05538d66a75cd0d4'
        msg += b'234b5ccf6c1715ccaaf9cdc0a2228135f716e'
        msg += b'e9bdee7fc13ec27a03a6d11c5c5b3685f5190'
        msg += b'0b1337153bc6c4e8f52920c33fa37f4e7'
        msg = c1.hextoascii(msg)
        x = b'c53eae6d45323164c7d07af5715703744a63fc3a'
        x = number.bytes_to_long(c1.hextoascii(x))
        y = b'313fd9ebca91574e1c2eebe1517c57e0c21b0209'
        y += b'872140c5328761bbb2450b33f1b18b409ce9ab7'
        y += b'c4cd8fda3391e8e34868357c199e16a6b2eba06'
        y += b'd6749def791d79e95d3a4d09b24c392ad89dbf1'
        y += b'00995ae19c01062056bb14bce005e8731efde17'
        y += b'5f95b975089bdcdaea562b32786d96f5a31aedf'
        y += b'75364008ad4fffebb970b'
        y = number.bytes_to_long(c1.hextoascii(y))
        params = p,q,g
        pub = y
        priv = x
        k = b'98cbcc4969d845e2461b5f66383dd503712bbcfa'
        k = number.bytes_to_long(c1.hextoascii(k))
        r, s, k = dsa_sign_with_k(msg, params, priv, k)
        sig = r,s
        r = c1.asciitohex(number.long_to_bytes(r))
        s = c1.asciitohex(number.long_to_bytes(s))
        self.assertEqual(r, b'50ed0e810e3f1c7cb6ac62332058448bd8b284c0'.upper())
        self.assertEqual(s, b'c6aded17216b46b7e4b6f2a97c1ad7cc3da83fde'.upper())
        self.assertTrue(dsa_verify(msg, sig, params, pub))
        self.assertEqual(get_x_from_k(msg, sig, params, k), x)

    def test_challenge_43(self):
        message = b'For those that envy a MC it can be hazardous to your health\n'
        message += b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'
        self.assertEqual(c1.asciitohex(sha1(message).digest()), b'd2d0714f014a9784047eaeccf956520045c45265'.upper())
        k          = random.randrange(1, 2**16)
        r          = 548099063082341131477253921760299949438196259240
        s          = 857042759984254168557880549501802188789837994940
        sig        = r,s
        k,x        = brute_force_k(message, sig, self.params, self.pub)
        xb         = hex(x)[2:].encode('ascii')
        r2, s2, k2 = dsa_sign_with_k(message, self.params, x, k)
        actual     = c1.asciitohex(sha1(xb).digest())
        self.assertEqual(actual, b'0954edd5e0afe5542a4adf012611a91912a3ec16'.upper())
        self.assertEqual(r2, r)
        self.assertEqual(s2, s)

if __name__ == "__main__":
    unittest.main()

"""
**Challenge 44**

*DSA Nonce Recovery From Repeated Nonce*

In this file find a collection of DSA-signed messages.

These were signed under the following pubkey::

   y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
       13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
       5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
       f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
       f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
       2971c3de5084cce04a2e147821

(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have
accidentally used a repeated 'k'. Given a pair of such messages, you
can discover the 'k' we used with the following formula::

         (m1 - m2)
    k = ----------- mod q
         (s1 - s2)

What is my private key? Its SHA-1 (from hex is)::

   ca8f6f7c66fa362d40760d135b763eb8527d3d52
"""
import sys, unittest, itertools
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set5')
import c1, c39, c43
from Crypto.Util import number
from hashlib import sha1

def recover_nonce(msg1, msg2, params):
    """
    Attempts to recover the nonce from the two messages, assuming both messages
    used the same nonce. If they, don't it returns None.

    Args:
        msg1: The first message
        msg2: The second message
        params: The DSA domain parameters

    Returns:
        The (k,x) pair from the two messages if they used the same nonce. If not,
        returns None.
    """
    p,q,g = params
    m1    = msg1.h
    m2    = msg2.h
    s1    = msg1.s
    s2    = msg2.s
    sig1  = msg1.r, msg1.s
    sig2  = msg2.r, msg2.s
    subm  = (m1 - m2) % q
    subs  = (s1 - s2) % q
    k     = (c39.invmod(subs, q) * subm) % q
    x1    = c43.get_x_from_k(msg1.msg, sig1, params, k)
    x2    = c43.get_x_from_k(msg2.msg, sig2, params, k)
    if x1 == x2:
        return k, x1
    return None

def find_repeated_k(msgs, params):
    """
    Looks for the pair of messages that used the same k and gets the
    private key from them.

    Args:
        msgs: All the messages
        params: DSA domain parameters

    Returns:
        The pair (k, x) obtained from the two messages that used the same k.
    """
    p,q,g = params

    for msg1, msg2 in itertools.combinations(msgs, 2):
        res = recover_nonce(msg1, msg2, params)
        if res:
            return res
    raise Error('unexpected')

def get_all_msgs():
    """
    Reads the file '../../testdata/44.txt' and constructs message objects
    from the values in the file.

    Returns:
        A list of Message objects
    """
    f     = open('../../testdata/44.txt')
    lines = f.readlines()
    f.close()
    i     = 0
    msgs  = []

    while i != len(lines):
        msg = lines[i][5:-1].encode('ascii')
        s   = int(lines[i+1][3:])
        r   = int(lines[i+2][3:])
        h   = int(lines[i+3][3:].encode('ascii'), 16)
        i   += 4
        msgs.append(Message(msg, r, s, h))

    return msgs


class Message():
    """
    Represents a Message structure containing the DSA signature and
    the SHA-1 hash digest.
    """
    def __init__(self, msg, r, s, h):
        self.msg = msg
        self.r = r
        self.s = s
        self.h = h

class TestChallenge44(unittest.TestCase):
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

        y = b'2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
        y += b'13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
        y += b'5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
        y += b'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
        y += b'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
        y += b'2971c3de5084cce04a2e147821'

        self.params = p,q,g
        self.pub = number.bytes_to_long(c1.hextoascii(y))

    def test_challenge_44(self):
        msgs = get_all_msgs()
        k, x = find_repeated_k(msgs, self.params)
        xb = hex(x)[2:].encode('ascii')
        xh = c1.asciitohex(sha1(xb).digest())
        self.assertEqual(xh, b'ca8f6f7c66fa362d40760d135b763eb8527d3d52'.upper())
        return

if __name__ == "__main__":
    unittest.main()
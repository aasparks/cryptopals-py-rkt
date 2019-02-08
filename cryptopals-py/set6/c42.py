"""
**Challenge 42**

*Bleichenbacher's e=3 RSA Attack*

RSA with an encrypting exponent of 3 is popular, because it makes the RSA math
faster.

With e=3 RSA, encryption is just cubing a number mod the public encryption
modulus::

   c = m ** 3 % n

e=3 is secure as long as we can make assumptions about the message blocks we're
encrypting. The worry with low-exponent RSA is that the message blocks we
process won't be large enough to wrap the modulus after being cubed. The block
00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA; it is
simply 00:08.

When you use RSA to sign a message, you supply it a block input that contains a
message digest. The PKCS1.5 standard formats that block as::

   00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH

As intended, the ffh bytes in that block expand to fill the whole block,
producing a "right-justified" hash (the last byte of the hash is the last byte
of the messsage).

There was, 7 years ago, a common implementation flaw with RSA verifiers: they'd
verify signatures by "decrypting" them (cubing them modulo the public exponent)
and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.

This is a bug because it implies the verifier isn't checking all the padding.
If you don't check the padding, you leave open the possibility that instead of
hundreds of ffh bytes, you have only a few, which if you think about it means
there could be squizzilions of possible numbers that could produce a
valid-looking signature.

How to find such a block? Find a number that when cubed (a) doesn't wrap the
modulus (thus bypassing the key entirely) and (b) produces a block that starts
"00h 01h ffh ... 00h ASN.1 HASH".

There are two ways to approach this problem:

 * You can work from Hal Finney's writeup, available on Google, of how
   Bleichenbacher explained the math "so that you can do it by hand with a
   pencil".
 * You can implement an integer cube root in your language, format the message
   block you want to forge, leaving sufficient trailing zeros at the end to
   fill with garbage, then take the cube-root of that block.

Forge a 1024-bit RSA signature for the string "hi mom". Make sure your
implementation actually accepts the signature!
"""
import sys, re, unittest
sys.path.insert(0, "../set1")
sys.path.insert(0, "../set5")
import c1, c39, c40
from Crypto.Util import number
from hashlib import sha1


def pkcs15_sign(message, priv):
    """
    RSASSA-PKCS1-V1_5-SIGN algorithm. Signs the message
    using PKCS1.5.

    Args:
        message: The message to be signed
        priv: The RSA private key

    Returns:
        The signature for the given message
    """
    d, n = priv
    k    = (n.bit_length() + 7) // 8
    em   = emsa_pkcs15_encode(message, k)
    m    = number.bytes_to_long(em)
    s    = RSASP1(m, priv)
    return number.long_to_bytes(s)

def pkcs15_verify(message, signature, pub):
    """
    RSASSA-PKCS1-V1_5-VERIFY algorithm. Verifies the given
    message, signature pair with the RSA public key. This process
    is secure, as defined in RFC 3447.

    Args:
        message: The message
        signature: The message signature
        pub: The RSA public key

    Returns:
        True if signature validates
    """
    e, n = pub
    k    = len(number.long_to_bytes(n))
    if len(signature) != k:
        raise ValueError("invalid signature")
    s        = number.bytes_to_long(signature)
    m        = RSAVP1(s, pub)
    em       = number.long_to_bytes(m, k)
    em_prime = emsa_pkcs15_encode(message, k)
    return em_prime == em

def emsa_pkcs15_encode(message, emLen):
    """
    EMSA-PKCS1.5-ENCODE

    Args:
        message: The message
        emLen: The length of the encoded message

    Returns:
        The encoded message.
    """
    H    = sha1(message).digest()
    der  = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    T    = der + H
    tLen = len(T)
    print(emLen)
    print(tLen + 11)
    if emLen < tLen + 11:
        raise ValueError('message length too short')
    ps = b'\xff' * (emLen - tLen - 3)
    return b'\x00\x01' + ps + b'\x00' + T

def RSAVP1(s, pub):
    """
    RSAVP1.

    Args:
        s: The signature representative
        pub: The RSA public key

    Returns:
        The message representative.
    """
    e, n = pub
    if 0 <= s < n:
        return pow(s, e, n)
    else:
        raise ValueError('signature representative out of range')

def RSASP1(m, priv):
    """
    RSASP1.

    Args:
        m: The message representative
        priv: The RSA private key

    Returns:
        The signature representative
    """
    d, n = priv
    if 0 <= m < n:
        return pow(m, d, n)
    else:
        raise ValueError('message representative out of range')

def pkcs15_verify_bad(message, signature, pub):
    """
    Bad PKCS1.5 verify algorithm that uses regular expression check

    Args:
        message: The message
        signature: The message signature
        pub: The RSA public key

    Returns:
        True if signature validates
    """
    m = c39.rsa_decrypt(signature, pub)
    m = c1.asciitohex(m)
    regexp = b'3021300906052B0E03021A05000414'
    r = re.compile(regexp)
    m = r.split(m)

    if len(m) != 2:
        return False
    h = c1.hextoascii(m[1])[:20]
    return h == sha1(message).digest()

def forge_signature(message):
    """
    Forges a signature that validates with a bad
    PKCS1.5 verifier.

    Args:
        message: The message to forge a signature for

    Returns:
        A valid signature for the given message.
    """
    pre = b'\x00\x01\xff\x00'
    asn = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    sha = sha1(message).digest()
    post = b'\x00' * (128 - 4 - len(asn) - 20)
    sig = b''.join([pre,asn,sha,post])
    sig = number.bytes_to_long(sig)
    sig = c40.find_invpow(sig, 3)[1]
    return number.long_to_bytes(sig)


class TestChallenge42(unittest.TestCase):
    def setUp(self):
        n =  b"c8a2069182394a2ab7c3f4190c15589c56"
        n += b"a2d4bc42dca675b34cc950e24663048441"
        n += b"e8aa593b2bc59e198b8c257e882120c623"
        n += b"36e5cc745012c7ffb063eebe53f3c6504c"
        n += b"ba6cfe51baa3b6d1074b2f398171f4b198"
        n += b"2f4d65caf882ea4d56f32ab57d0c44e6ad"
        n += b"4e9cf57a4339eb6962406e350c1b153971"
        n += b"83fbf1f0353c9fc991"
        n = c1.hextoascii(n)
        n = number.bytes_to_long(n)

        e = b"010001"
        e = c1.hextoascii(e)
        e = number.bytes_to_long(e)

        d = b"5dfcb111072d29565ba1db3ec48f57645"
        d += b"d9d8804ed598a4d470268a89067a2c921"
        d += b"dff24ba2e37a3ce834555000dc868ee65"
        d += b"88b7493303528b1b3a94f0b71730cf1e8"
        d += b"6fca5aeedc3afa16f65c0189d810ddcd8"
        d += b"1049ebbd0391868c50edec958b3a2aaef"
        d += b"f6a575897e2f20a3ab5455c1bfa55010a"
        d += b"c51a7799b1ff8483644a3d425"
        d = c1.hextoascii(d)
        d = number.bytes_to_long(d)

        self.pub  = e, n
        self.priv = d, n

        m1 = b"e8312742ae23c456ef28a23142"
        m1 += b"c4490895832765dadce02afe5b"
        m1 += b"e5d31b0048fbeee2cf218b1747"
        m1 += b"ad4fd81a2e17e124e6af17c388"
        m1 += b"8e6d2d40c00807f423a233cad6"
        m1 += b"2ce9eaefb709856c94af166dba"
        m1 += b"08e7a06965d7fc0d8e5cb26559"
        m1 += b"c460e47bc088589d2242c9b3e6"
        m1 += b"2da4896fab199e144ec136db8d"
        m1 += b"84ab84bcba04ca3b90c8e5"
        self.m1 = c1.hextoascii(m1)
        s1 = b"28928e19eb86f9c00070a59edf6bf843"
        s1 += b"3a45df495cd1c73613c2129840f48c4a"
        s1 += b"2c24f11df79bc5c0782bcedde97dbbb2a"
        s1 += b"cc6e512d19f085027cd575038453d04905"
        s1 += b"413e947e6e1dddbeb3535cdb3d8971fe020"
        s1 += b"0506941056f21243503c83eadde053ed866"
        s1 += b"c0e0250beddd927a08212aa8ac0efd61631"
        s1 += b"ef89d8d049efb36bb35f"
        self.s1 = c1.hextoascii(s1)

        m2 = b"207102f598ec280045be67592f5bba25"
        m2 += b"ba2e2b56e0d2397cbe857cde52da8cca"
        m2 += b"83ae1e29615c7056af35e8319f2af86f"
        m2 += b"dccc4434cd7707e319c9b2356659d7886"
        m2 += b"7a6467a154e76b73c81260f3ab443cc03"
        m2 += b"9a0d42695076a79bd8ca25ebc8952ed44"
        m2 += b"3c2103b2900c9f58b6a1c8a6266e43880"
        m2 += b"cda93bc64d714c980cd8688e8e63"
        self.m2 = c1.hextoascii(m2)
        s2 = b"77f0f2a04848fe90a8eb35ab5d94cae843db"
        s2 += b"61024d0167289eea92e5d1e10a526e420f2d"
        s2 += b"334f1bf2aa7ea4e14a93a68dba60fd2ede58"
        s2 += b"b794dcbd37dcb1967877d6b67da3fdf2c0c7"
        s2 += b"433e47134dde00c9c4d4072e43361a767a52"
        s2 += b"7675d8bda7d5921bd483c9551950739e9b2b"
        s2 += b"e027df3015b61f751ac1d9f37bea3214d3c8dc96"
        self.s2 = c1.hextoascii(s2)

    def test_pkcs15(self):
        self.assertEqual(pkcs15_sign(self.m1, self.priv), self.s1)
        self.assertTrue(pkcs15_verify(self.m1, self.s1, self.pub))
        self.assertTrue(pkcs15_verify_bad(self.m1, self.s1, self.pub))
        self.assertEqual(pkcs15_sign(self.m2, self.priv), self.s2)
        self.assertTrue(pkcs15_verify(self.m2, self.s2, self.pub))
        self.assertTrue(pkcs15_verify_bad(self.m2, self.s2, self.pub))

    def test_challenge_42(self):
        s = forge_signature(self.m1)
        e,n = self.pub
        pub = 3,n
        self.assertTrue(pkcs15_verify_bad(self.m1, s, pub))
        with self.assertRaises(ValueError):
            pkcs15_verify(self.m1, s, pub)
        s = forge_signature(self.m2)
        self.assertTrue(pkcs15_verify_bad(self.m2, s, pub))
        with self.assertRaises(ValueError):
            pkcs15_verify(self.m2, s, pub)

if __name__ == "__main__":
    unittest.main()

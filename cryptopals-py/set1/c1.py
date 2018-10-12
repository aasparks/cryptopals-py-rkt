"""
**Challenge 1**

*Convert hex to base64*

The string:

``49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d``

Should produce:

``SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t``

So go ahead and make that happen. You'll need to use this code
for the rest of the exercises.

"""
import base64, unittest

def hextoascii(hexbstr):
    """
    Converts a bytestring in hex representation to ASCII.

    Args:
        hexbstr: a bytestring encoded in hex.

    Returns:
        The bytestring decoded into ASCII.
    """
    return base64.b16decode(hexbstr.upper())

def asciitohex(abstr):
    """
    Encodes an ASCII bytestring into hex representation.

    Args:
        abstr: ASCII bytestring to encode.

    Returns:
        The bytestring encoded in hex.
    """
    return base64.b16encode(abstr)

def hextobase64(hexbstr):
    """
    Encodes a hex-encoded string into base64.

    Args:
        hexbstr: A bytestring in hex representation.

    Returns:
        The bytestring encoded in base64 representation.
    """
    return base64.b64encode(hextoascii(hexbstr))

def base64tohex(b64bstr):
    """
    Encodes a base64 bytestring into a hex-encoded bytestring.

    Args:
        b64bstr: A bytestring encoded in base64.

    Returns:
        The bytestring encoded in hex.
    """
    return asciitohex(base64.b64decode(b64bstr))

def asciitobase64(abstr):
    """
    Encodes an ASCII bytestring into base64.

    Args:
        abstr: An ASCII bytestring.

    Returns:
        The bytestring encoded in base64.
    """
    return base64.b64encode(abstr)

def base64toascii(b64bstr):
    """
    Decodes a base64 bytestring into ASCII.

    Args:
        b64bstr: A bytestring in base64

    Returns:
        The bytestring decoded into ASCII
    """
    return base64.b64decode(b64bstr)

class TestConversions(unittest.TestCase):
    __pdoc__ = dict()
    for field in unittest.TestCase.__dict__.keys():
        __pdoc__['TestConversions.%s' % field] = None
    def setUp(self):
        self.asc = b'Who lives in a pineapple under the sea?'
        self.hx  = b'57686f206c6976657320696e20612070696e656170706c6520756e64657220746865207365613f'
        self.b64 = b'V2hvIGxpdmVzIGluIGEgcGluZWFwcGxlIHVuZGVyIHRoZSBzZWE/'

    def test_hex_ascii(self):
        self.assertEqual(hextoascii(self.hx), self.asc)
        self.assertEqual(asciitohex(self.asc), self.hx.upper())

    def test_hex_base64(self):
        self.assertEqual(hextobase64(self.hx), self.b64)
        self.assertEqual(base64tohex(self.b64), self.hx.upper())

    def test_base64_ascii(self):
        self.assertEqual(asciitobase64(self.asc), self.b64)
        self.assertEqual(base64toascii(self.b64), self.asc)

    def test_challenge_1(self):
        hxstr  = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        b64str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(hextobase64(hxstr), b64str)

if __name__ == "__main__" :
    unittest.main()

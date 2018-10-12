"""
**Challenge 2**

*Fixed XOR*

Write a function that takes two equal-length buffers and produces
their XOR combination.

If your function works properly, then when you feed it the string:

``1c0111001f010100061a024b53535009181c``

...after hex decoding, and when XOR'd against:

``686974207468652062756c6c277320657965``

...should produce:

``746865206b696420646f6e277420706c6179``

"""
import c1, unittest

def xorstrs(str1, str2):
    """
    XOR's two bytestrings together

    Args:
        bstr1: The first bytestring
        bstr2: The second bytestring

    Returns:
        A bytestring containing the result of XORing the two arguments

    Raises:
        ValueError if the strings are not equal length
    """
    # Check strings for each length
    if len(str1) != len(str2):
        msg = 'Input strings must be equal length. Received: '
        msg += str(len(str1)) + ', ' + str(len(str2))
        raise ValueError(msg)

    out = []
    for (c, k) in zip(str1, str2):
        out.append(bytes([c ^ k]))
    return b''.join(out)

# Test cases
class TestXOR(unittest.TestCase):
    def setUp(self):
        self.str1 = c1.hextoascii(b'1c0111001f010100061a024b53535009181c')
        self.str2 = c1.hextoascii(b'686974207468652062756c6c277320657965')

    def test_error_check(self):
        with self.assertRaises(ValueError):
            xorstrs(self.str1, self.str2[0:-1])

    def test_challenge_2(self):
        actual   = c1.asciitohex(xorstrs(self.str1, self.str2))
        expected = b'746865206b696420646f6e277420706c6179'.upper()
        self.assertEqual(actual, expected)


if __name__ == "__main__" :
    unittest.main()

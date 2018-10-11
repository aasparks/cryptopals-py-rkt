"""
Challenge 15
PKCS7 Padding Validation

Write a function that takes a plaintext, determines if it has valid
PKCS#7 padding, and strips the padding off.

The string:
    "ICE ICE BABY\x04\x04\x04\x04"
...has valid padding, and produces the result
    "ICE ICE BABY"

The string:
    "ICE ICE BABY\x05\x05\x05\x05"
...does not have valid padding, nor does:
    "ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make
your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""
import c9, unittest

# I already did this for c9. I don't know why they break it up
# like this when you need unpad in the previous exercises.

class TestPKCS7Unpad(unittest.TestCase):
    def test_challenge_15(self):
        expected = b'ICE ICE BABY'
        t1 = b'ICE ICE BABY\x04\x04\x04\x04'
        t2 = b'ICE ICE BABY\x05\x05\x05\x05'
        t3 = b'ICE ICE BABY\x01\x02\x03\x04'
        self.assertEqual(c9.pkcs7_unpad(t1), expected)

        with self.assertRaises(c9.PaddingError):
            c9.pkcs7_unpad(t2)
        with self.assertRaises(c9.PaddingError):
            c9.pkcs7_unpad(t3)

if __name__ == '__main__':
    unittest.main()

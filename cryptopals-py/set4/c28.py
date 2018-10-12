"""
**Challenge 28**

*Implement a SHA-1 Keyed MAC*

Find a SHA-1 implementation in the language you code in.

Write a function to authenticate a message under a secret key by using a
secret-prefix MAC, which is simply::

    SHA1(key || message)

Verify that you cannot tamper with the message without breaking the MAC you've
produced, and that you can't produce a new MAC without knowing the secret key.
"""
import os, unittest
from MYSHA1 import MYSHA1 as sha1

key = os.urandom(16)
def mac_sha1(message):
    """
    Creates a message authentication code using SHA-1.

    Args:
        message: The message to create a code for.

    Returns:
        The MAC generated from the message by using SHA-1.
    """
    return sha1(key+message).digest()

class TestMACSHA1(unittest.TestCase):
    def test_challenge_28(self):
        msg = b'The krabby patty formula is in box1'
        msg1 = b'The krabby patty formula is in box2'
        self.assertEqual(mac_sha1(msg), mac_sha1(msg))
        self.assertNotEqual(mac_sha1(msg), mac_sha1(msg1))

if __name__ == "__main__":
    unittest.main()
"""
Challenge 9
Implement PKCS7 padding

A block cipher transforms a fixed-sized block of plaintext into
ciphertext. But we almost never want to transform a single block; we
encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding,
creating a plaintext that is an even multiple of the blocksize. The most
popular padding scheme is called PKCS#7.

So; pad any block to a specific block length, by appending the number
of bytes of padding to the end of the block. For instance,
"YELLOW SUBMARINE"
... padded to 20 bytes would be
"YELLEOW SUBMARINE\x04\x04\x04\x04"
"""
import unittest

def pkcs7_pad(txt, n=16):
    """
    Adds padding according to the PKCS#7 standard.

    Args:
        txt: The text to be padded
        n (optional): The blocksize. Defaults to 16 bytes

    Returns:
        The bytestring padded out to a multiple of blocksize
    """
    num = n - (len(txt) % n)
    return txt + bytes([num] * num)

# Unpads and checks that padding is valid
def pkcs7_unpad(txt, n=16):
    """
    Unpads according to PKCS#7 with padding validation.

    Args:
        txt: The text to unpad.
        n (optional): The blocksize
    """
    idx      = len(txt) - 1
    num_pads = txt[-1]

    if num_pads > n or num_pads == 0:
        raise PaddingError('Last padding byte is invalid')

    for i in range(num_pads):
        if txt[idx] != num_pads:
            raise PaddingError('Invalid padding byte ' + str(txt[idx]))
        idx -= 1
    return txt[:idx+1]

class PaddingError(Exception):
    pass

class TestPKCS7(unittest.TestCase):
    def test_pad(self):
        str1 = b'Spongebob Squarepants'
        str2 = pkcs7_pad(str1, 16)
        str3 = pkcs7_pad(str1, 4)
        self.assertEqual(str2, str1 + b'\x0b' * 11)
        self.assertEqual(str3, str1 + b'\x03' * 3)

    def test_unpad(self):
        str1 = b'Spongebob Squarepants'
        str2 = pkcs7_unpad(str1 + b'\x0b' * 11)
        self.assertEqual(str1, str2)
        with self.assertRaises(PaddingError):
            pkcs7_unpad(str1)
        with self.assertRaises(PaddingError):
            pkcs7_unpad(str2[0:-1])

    def test_challenge_9(self):
        str1 = b'YELLOW SUBMARINE'
        str2 = pkcs7_pad(str1, 20)
        self.assertEqual(str2, str1 + b'\x04\x04\x04\x04')

if __name__ == "__main__" :
    unittest.main()

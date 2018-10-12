"""
**Challenge 32 - SERVER**

*Implement and Break HMAC-SHA1 with an Artificial Timing Leak*

Reduce the sleep in your "insecure_compare" until your previous solution breaks.
(Try 5ms to start)

Now break it again.
"""
import sys, os, web, time, unittest, threading
sys.path.insert(0, '../set1')
import c1, c2
from MYSHA1 import MYSHA1 as sha1

DEBUG = False
DELAY = 0.03

def hmac_sha1(key, message):
    """
    Creates an HMAC using SHA-1.

    Args:
        key: The HMAC key.
        message: The message to generate the MAC for.

    Returns:
        The HMAC for the message under the given key
    """
    # If the key is longer than the blocksize,
    # then truncate it by hashing it
    if (len(key) > 64):
        key = sha1(key).digest()

    # If the key is shorter than blocksize,
    # pad with 0s
    if (len(key) < 64):
        key = key + (b'\x00' * (64 - len(key)))

    o_pad = c2.xorstrs(key, b'\x5c'*64)
    i_pad = c2.xorstrs(key, b'\x36'*64)
    i_msg = i_pad + message
    o_msg = o_pad + sha1(i_msg).digest()
    return sha1(o_msg).digest()

def insecure_compare(str1, str2):
    """
    Compares two strings for equality with an artificial timing leak.

    Args:
        str1: The first string
        str2: The second string

    Returns:
        True if the strings are equal.
    """
    if DEBUG:
        print(c1.asciitohex(str1))
        print(c1.asciitohex(str2))
    result = True
    if len(str1) != len(str2):
        return False
    for i in range(len(str1)):
        result &= str1[i] == str2[i]
        if result:
            time.sleep(DELAY)
        else:
            return result
    return result

urls = ('/', 'index')
key  = os.urandom(16)

class index:
    def GET(self):
        user_data = web.input(file='', signature='')

        if user_data.file == "" or user_data.signature == "":
            return 500

        expected = hmac_sha1(key, user_data.file.encode('utf-8'))
        actual   = c1.hextoascii(user_data.signature)
        if insecure_compare(expected, actual):
            return 200
        else:
            return 500

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
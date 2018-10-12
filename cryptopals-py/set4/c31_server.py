"""

**Challenge 31 - SERVER**

*Implement and Break HMAC-SHA1 with an Artificial Timing Leak*

The pseudocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing, write a tiny application that
has a URL that takes a "file" argument and a "signature" argument, like so:

``http://localhost:9000/test?file=foo&signature=bar``

Have the server generate an HMAC key, and then verify that the signature on
incoming requests is valid for 'file', using the '==' operator to compare the
valid MAC for a file with the signature parameter (in other words, verify the
HMAC the way any normal programmer would verify it).

Write a function, call it ``insecure_compare``, that implements the == operation
by doing byte-at-a-time comparisons with early exit (ie, return false at the
first non-matching byte).

In the loop for ``insecure_compare``, add a 50ms sleep (sleep 50ms after each byte)

Use your ``insecure_compare`` function to verify the HMACs on incoming requests,
and test that the whole contraption works. Return a 500 if the MAC is invalid,
and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the
valid MAC for any file.
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
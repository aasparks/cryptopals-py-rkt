"""
**Challenge 13**

*ECB cut-and-paste*

Write a k=v parsing routine, as if for a structured cookie. The routine
should take:

``foo=bar&baz=qux&zap=zazzle``

...and produce::

    {
        foo: 'bar',
        baz: 'qux',
        zap: 'zazzle'
    }

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email
address. You should have something like::

    profile_for("foo@bar.com")

...and it should produce::

    {
        email: 'foo@bar.com',
        uid: 10,
        role: 'user'
    }

...encoded as

``email=foo@bar.com&uid=10&role=user``

You "profile_for" function should not allow encoding metacharacters (& and =).
Eat them, quote them, whatever you want to do, but don't let people set their
email address to

``"foo@bar.com&role=admin"``.

Now, two more easy functions. Generate a random AES key, then:
* A. Encrypt the encoded user profile under the key; "provide" that to the
"attacker".
* B. Decrypt the encoded user profile and parse it.

Using only the user input to ``profile_for()`` (an an oracle to generate "valid"
ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""
import sys, os, unittest
sys.path.insert(0, '../set1')
import c6, c9
from Crypto.Cipher import AES

uid = 0
key = os.urandom(16)

def parse_cookie(cookie):
    """
    Parses a cookie as described above and produces a dictionary with the
    values.

    Args:
        cookie: The cookie encoded as foo=bar&baz=qux&zap=zazzle

    Return:
        A dictionary containing the key,value pairs from the cookie as
        described above.
    """
    # First split the string into entries
    entries = cookie.split("&")
    # For each each entry, find the = and
    # save each side in the dictionary
    result = dict()
    for entry in entries:
        left, right = entry.split("=")
        result[left] = right
    return result

def profile_for(email):
    """
    Generates a profile for the given email address with a user id and the
    role set to user.

    Args:
        email: The profile's email address

    Returns:
        A cookie for the user's profile encoded as email=foo&uid=1&role=user
    """
    global uid
    uid += 1
    em  = "email=" + email.translate(str.maketrans("", "", "&="))
    ud  = "&uid=" + str(uid)
    rl  = "&role=user"
    return em + ud + rl

# Encrypt the encoded user profile under a random key
def encode_profile(email):
    """
    Encrypts the encoded profile cookie for the given email address.

    Args:
        email: The user's email address

    Return:
        The encrypted cookie
    """
    prof = profile_for(email).encode("utf-8")
    return AES.new(key, AES.MODE_ECB).encrypt(c9.pkcs7_pad(prof))

# Decrypt the user profile and parse it
def decode_profile(ct):
    """
    Decodes the encrypted cookie and parses it into a dictionary.

    Args:
        ct: The encrypted cookie containing the profile information

    Returns:
        A dictionary containing the profile's information
    """
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return parse_cookie(c9.pkcs7_unpad(pt).decode("utf-8"))

# Using only the user input  to profile_for() and the ct themselves,
# make a role=admin profile.
def fake_admin():
    """
    Creates a fake admin account using ECB cut-and-paste attack

    Returns:
        The decoded profile as a dictionary with dict[role] == admin
    """
    # This attack involves block alignment.
    #
    # 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    # email=sponge@bob .com&uid=2&role= user
    # email=blahblahbl adminBBBBBBBBBBB &uid=3&role=user
    # Cut and paste the blocks you want
    #      email=spongebobsquar&uid=2&role=admin0000000000B
    first_entry  = encode_profile("sponge@bob.com")
    second_entry = encode_profile("blahblahbladmin" + '\x0B' * 11)
    bad_cookie   = first_entry[:32] + c6.get_block(second_entry, 1, 16)
    return decode_profile(bad_cookie)

class TestECBCutAndPaste(unittest.TestCase):
    def test_parse_cookie(self):
        actual = parse_cookie("foo=bar&baz=qux&zap=zazzle")
        expected = {"foo" : "bar", "baz" : "qux", "zap" : "zazzle"}
        self.assertEqual(actual, expected)

    def test_profile_for(self):
        global uid
        uid = 0
        email1 = "foo@bar.com"
        email2 = "foo@bar.com&role=admin"
        expected1 = "email=foo@bar.com&uid=1&role=user"
        expected2 = "email=foo@bar.comroleadmin&uid=2&role=user"
        self.assertEqual(profile_for(email1), expected1)
        self.assertEqual(profile_for(email2), expected2)

    def test_challenge_13(self):
        global uid
        uid = 0
        result = fake_admin()
        self.assertEqual(result["email"], "sponge@bob.com")
        self.assertEqual(result["role"], "admin")

if __name__ == "__main__" :
    unittest.main()

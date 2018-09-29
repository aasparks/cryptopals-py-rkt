# Challenge 13
## ECB cut-and-paste
import sys, os
sys.path.insert(0, '../set1')
import c6, c9
from Crypto.Cipher import AES

uid = 0
key = os.urandom(16)
# Accepts a string formatted as
#   foo=bar&baz=qux&zap=zazzle
# and produces a dictionary
# {
#    foo: 'bar',
#    baz: 'qux',
#    zap: 'zazzle'
# }
def parse_cookie(cookie):
    # First split the string into entries
    entries = cookie.split("&")
    # For each each entry, find the = and
    # save each side in the dictionary
    result = dict()
    for entry in entries:
        left, right = entry.split("=")
        result[left] = right
    return result

# Given email address
#    foo@bar.com
# Produces the dictionary
# {
#     email: 'foo@bar.com',
#     uid: 10,
#     role: 'user'
# }
# Encoded as
#    email=foo@bar.com&uid=10&role=user
def profile_for(email):
    global uid
    uid += 1
    em  = 'email=' + email.translate(None, '&=')
    ud  = '&uid=' + str(uid)
    rl  = '&role=user'
    return em + ud + rl

# Encrypt the encoded user profile under a random key
def encode_profile(email):
    return AES.new(key, AES.MODE_ECB).encrypt(c9.pkcs7_pad(profile_for(email)))

# Decrypt the user profile and parse it
def decode_profile(ct):
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return parse_cookie(c9.pkcs7_unpad(pt))

# Using only the user input  to profile_for() and the ct themselves,
# make a role=admin profile.
def fake_admin():
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

def test_parse_cookie():
    result   = parse_cookie("foo=bar&baz=qux&zap=zazzle")
    expected = {'foo' : 'bar', 'baz' : 'qux', 'zap' : 'zazzle'}
    assert str(result) == str(expected)

def test_profile_for():
    email  = "foo@bar.com"
    result = profile_for(email)
    assert result == "email=foo@bar.com&uid=1&role=user"

def main():
    test_parse_cookie()
    test_profile_for()
    result = fake_admin()
    assert result['email'] == 'sponge@bob.com'
    assert result['role']  == 'admin', result['role']

if __name__ == "__main__" : main()

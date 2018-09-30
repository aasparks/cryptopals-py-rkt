# Challenge 17
## The CBC Padding Oracle

import sys, os, random
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
import c10, c9, c6, c2, c1

key = os.urandom(16)
iv  = os.urandom(16)
strs = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
       "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
       "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
       "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
       "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
       "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
       "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
       "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
       "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
       "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

# This problem is a bit tough to grasp.
# My best resource for this was BY FAR:
#    http://www.exploresecurity.com/padding-oracle-decryption-attack/

# The encryption oracle. Picks a random string
# and encrypts it.
def encryption_oracle():
    pt = random.choice(strs)
    pt = c1.base64toascii(pt)
    pt = c9.pkcs7_pad(pt)
    return c10.aes_128_cbc_encrypt(pt, key, iv)

# The decryption oracle. Really the padding oracle.
# Decrypts and determines if the padding is valid.
def decryption_oracle(txt):
    ct = c10.aes_128_cbc_decrypt(txt, key, iv)
    try:
        #print 'Pad byte: ' + str(ord(ct[-1]))
        ct = c9.pkcs7_unpad(ct)
        return True
    except:
        return False

# The actual attack. Implemented top-down, we can
# ignore the real magic. This just iterates through
# the blocks backwards.
def cbc_padding_attack():
    # The IV is given so we can get all blocks
    txt        = iv + encryption_oracle()
    num_blocks = len(txt) / 16
    result     = ''
    for i in reversed(range(1, num_blocks)):
        result = attack_block(txt, i) + result
    return c9.pkcs7_unpad(result)

# Basically the same thing as the last problem, it just
# iterates through each byte backwards.
def attack_block(txt, block_num):
    plaintext  = ''
    block      = c6.get_block(txt, block_num)
    prev_b     = c6.get_block(txt, block_num - 1)
    for i in reversed(range(16)):
        p = attack_byte(block, prev_b, i, plaintext)
        plaintext = p + plaintext
    return plaintext

# This is where the magic happens.
def attack_byte(block, prev_block, byte_num, plaintext):
    # Knownxor is super tricky. Read the link from the top comment.
    # We want all the last values to be good padding.
    # To do this we xor the prev_block with the known plaintext with
    #  the value we want to get for padding.
    knownxor = ''
    if (len(plaintext) > 0):
        knownxor = c2.xorstrs(prev_block[-len(plaintext):], plaintext)
        knownxor = c2.xorstrs(chr(16-byte_num) * len(plaintext), knownxor)
    # Test each byte, returning when the padding is valid.
    for i in range(1, 256):
        bad_prev_b = chr(0) * byte_num
        # The magic here will only allow for valid padding when i is
        # the same as the value of the original plaintext.
        bad_prev_b += chr(i ^ (16-byte_num) ^ ord(prev_block[byte_num]))
        bad_prev_b += knownxor
        if (decryption_oracle(bad_prev_b + block)):
            return chr(i)
    raise Exception

if __name__ == "__main__" :
    random.seed(1)
    expected = b'000002Quick to the point, to the point, no faking'
    actual   = cbc_padding_attack()
    assert expected == actual, actual

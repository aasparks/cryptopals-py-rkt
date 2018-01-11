# Challenge 16
## CBC Bitflipping Attacks
import sys
sys.path.insert(0, '../set1')
import c10, c9, c6
import os
# Generate a random AES key
key = os.urandom(16)

# Combine your padding code and CBC code to write two functions.
# The first function should take an arbitrary input string, prepend
#  the string:
prefix = 'comment1=cooking%20MCs;userdata='
# ... and append the string:
suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

def encrypt_userdata(data):
    # The function should quote out the ';' and '=' characters.
    new_c  = prefix + data.replace(';', '').replace('=', '') + suffix
    # The function should then pad out the input to the 16-byte
    # AES block length and encrypt it under the random AES key
    new_c = c9.pkcs7_pad(new_c)
    return c10.aes_128_cbc_encrypt(new_c, key)

# The second function should decrypt the string and look for 
# the characters ';admin=true;'. Return true if found.
def is_admin(cookie):
    data = c10.aes_128_cbc_decrypt(cookie, key)
    data = c9.pkcs7_unpad(data)
    return ';admin=true;' in data


## Okay let's think about this.
# You're relying on the fact that in CBC mode,
# a 1-bit error in a ciphertext block:
#  - completely scrambles the block the error occurs in
#  - produces a the identical 1-bit error in the next block
## Okay so maybe we cut and paste blocks like we did with ECB
### 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
### comment1=cooking %20MCs;userdata= XadminXtrueX
## So I should be able to send the above as my data
## and then send it in with the right bit flips to
## make the X's the characters I want.
def cbc_attack():
    data = 'XadminXtrueX'
    original = encrypt_userdata(data)
    cracked = original[:16]
    cracked += convert_char(original[16], 'X', ';')
    cracked += original[17:22]
    cracked += convert_char(original[22], 'X', '=')
    cracked += original[23:27]
    cracked += convert_char(original[27], 'X', ';')
    cracked += original[28:]
    assert is_admin(cracked)

def convert_char(orig, now, later):
    return chr(ord(orig) ^ ord(now) ^ ord(later))


if __name__ == "__main__" :
    cbc_attack()

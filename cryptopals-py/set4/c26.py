# Challenge 26
## CTR Bitflipping
import sys, os
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
sys.path.insert(0, '../set3')
import c18

### There are people in the world that believe that CTR
### resists bit flipping attacks of the kind to which
### CBC mode is susceptible.
### Re-implement the CBC bitflipping exercise from earlier
### to use CTR mode instead of CBC mode. Inject an 
### 'admin=true' token.

key = os.urandom(16)
prefix = 'comment1=cooking%20MCs;userdata='
suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

# Encrypt user data as a cookie exactly like the last challenge
# but using CTR mode instead
def encrypt_userdata(data):
    new_c = prefix + data.replace(';', '').replace('=', '') + suffix
    return c18.aes_128_ctr(new_c, key)

# Exactly the same as last time. Determines
# if a cookie has the admin string
def is_admin(cookie):
    data = c18.aes_128_ctr(cookie, key)
    return ';admin=true;' in data

# How does this differ from the CBC attack?
## PT ^ KEY = CT
## CT ^ KEY = PT
## PT ^ ATTACK = MY_PT
## CT ^ KEY ^ ATTACK = MY_PT
# So what should attack be?
# I think this is actually the same, except
# you don't attack the previous block. You just attack
# the block you want to change.
def ctr_attack():
    data  = 'XadminXtrue'
    original = encrypt_userdata(data)
    cracked = original[:32]
    cracked += convert_char('X', ';', original[32])
    cracked += original[33:38]
    cracked += convert_char('X', '=', original[38])
    cracked += original[39:]
    return is_admin(cracked)

# Same as original. XOR all the chars
def convert_char(a, b, c):
    return chr(ord(a) ^ ord(b) ^ ord(c))

def main():
    assert ctr_attack()

if __name__ == '__main__' : main()

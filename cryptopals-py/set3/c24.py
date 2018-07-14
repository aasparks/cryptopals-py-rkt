# Challenge 24
## Create the MT19937 stream cipher and break it
import sys, os, random, time
sys.path.insert(0, '../set1')
import c2, c21
### You can create a trivial stream cipher out of any PRNG; use it
### to generate a sequence of 8-bit outputs and call those outputs
### a keystream. XOR each byte of plaintext with each successive
### byte of keystream.
###
### Write the function that does this for MT19937 using a 16-bit seed.
### Verify that you can encrypt and decrypt properly. This code should
### look similar to your CTR code.
def encrypt(txt, seed):
    mt = c21.MT19937(seed)
    num_bytes = len(txt)
    keystream = ''
    for i in range(num_bytes):
        keystream += chr(mt.generate_number() & 0xFF)
    return c2.xorstrs(txt, keystream)

def decrypt(txt, seed):
    return encrypt(txt, seed)

### Use your function to encrypt a known plaintext
### (say, 14 A's prefixed by a random number of random
### characters)
def test_cipher():
    orig = os.urandom(14)
    orig += 'A' * 14
    ct = encrypt(orig, 455)
    pt = decrypt(ct, 455)
    assert pt == orig, pt

###  From the ciphertext, recover the 'key' (the seed).
def encryption_oracle(txt):
    prefix = os.urandom(random.randint(10, 20))
    return encrypt(prefix + txt, 123) # gonna use a constant seed for testing

def get_seed():
    orig = 'A' * 14
    orig_ct = encryption_oracle(orig)
    for i in range(2**16):
        pt = decrypt(orig_ct, i)
        if pt[-14:] == orig:
            return i
    raise Exception('seed not found')

def test_get_seed():
    assert get_seed() == 123


### Use the same idea to generate a random "password reset
### token" using MT19937 seeded from the current time.
def password_reset():
    seed = int(time.time())
    mt = c21.MT19937(seed)
    token = ''
    for i in range(6):
        token += chr(mt.generate_number() & 0xFF)
    return token

def is_valid_token(token):
    start_seed = int(time.time())
    # Don't go too far back
    for i in range(2000):
        mt = c21.MT19937(start_seed - i)
        n_token = ''
        for i in range(6):
            n_token += chr(mt.generate_number() & 0xFF)
        if n_token == token:
            return True
    return False

def main():
    test_cipher()
    test_get_seed()
    assert is_valid_token(password_reset())

if __name__ == "__main__" : main()

# Challenge 12
## Byte-at-a-time ECB Decryption (Simple)
import os, sys
from Crypto.Cipher import AES
sys.path.insert(0, '../set1')
import c1, c6, c9


key = os.urandom(16)
unknown = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
unknown += 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
unknown += 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown = c1.base64toascii(unknown)
blocksize = 0

# Encryption oracle
def encryption_oracle(txt):
    return AES.new(key, AES.MODE_ECB).encrypt(c9.pkcs7_pad(txt + unknown))

# 1. Feed identical bytes of your-string to the function 1 at a time.
#    Discover the block size of the cipher.
def get_blocksize():
    # Send strings of length 0-40
    prev_len = len(encryption_oracle(''))
    prev_block = -1
    for i in range(1, 40):
        ct = encryption_oracle(('A' * i))
        # If the length increases by more than 1
        # we have jumped up a block
        if len(ct) > prev_len:
            block = i
            # If this is the second time, we know the block size
            if prev_block > 0:
                return i - prev_block
            # If this is the first time, we save it
            else:
                prev_block = block
        # Keep going
        prev_len = len(ct)
    return -1

# 2. Detect that the function is using ECB.
def is_ecb():
    ct = encryption_oracle(('A' * blocksize * 3))
    return c6.get_block(ct, 0, blocksize) == c6.get_block(ct, 1, blocksize)

# 3. Knowing the block size, craft an input block that is 
#    exactly 1 byte short.
def craft_block(offset, num_bytes):
    return 'A' * (num_bytes - 1 - offset) 

# 4. Make a dictonary of every possible last byte by feeding different
#    strings to the oracle, remember the first block of each invocation.
# 5. Match the output of the one-byte-short input to one of the entries
#    in your dictionary.
def decode_byte(known, num_bytes):
    # Just stop when we find the match. No need to save
    # a dictionary
    prefix   = craft_block(len(known), num_bytes)
    original = encryption_oracle(prefix)
    length   = len(prefix) + len(known) + 1
    for i in range(256):
        ct = encryption_oracle(prefix + known + chr(i))
        if (ct[:length] == original[:length]):
            return chr(i)
    return -1 

def decode_secret():
    e_secret = encryption_oracle('')
    num_bytes = len(e_secret)
    secret = ''
    c = ''
    # It may not be exactly num_bytes because of padding.
    # Run until we get back -1.
    c = decode_byte(secret, num_bytes)
    while c > -1:
        secret += c
        c = decode_byte(secret, num_bytes)

    return secret


def main():
    global blocksize
    blocksize = get_blocksize()
    assert blocksize > 0
    assert is_ecb()
    print decode_secret()

if __name__ == "__main__" : main()

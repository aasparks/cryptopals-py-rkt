# Challenge 11
## An ECB/CBC detection oracle
from Crypto.Cipher import AES
import os, random
import c9, c10
import c1, c8

# ENCRYPT using an unknown mode with random data inserted
def encryption_oracle(txt):
    # GENERATE random key
    key = os.urandom(16)
    # GENERATE random number for ECB or CBC
    ecb = random.randint(0, 1)
    # APPEND random bytes before and after
    before = os.urandom(random.randint(5, 10))
    after  = os.urandom(random.randint(5, 10))
    txt = before + txt + after
    txt = c9.pkcs7_pad(txt)
    ct = ''
    # IF CBC
    if (ecb == 0):
        # GENERATE random IV
        iv = os.urandom(16)
        ct = c10.aes_128_cbc_encrypt(txt, key, iv)
    # ENCRYPT
    else:
        ct = AES.new(key, AES.MODE_ECB).encrypt(txt)
    return ct

# Determines if the encryption is ECB or CBC
# There's a few questions here. Can we detect CBC mode
# easily like we can with ECB? Not really. But it is safe
# to assume that ECB and CBC are the only ones being used
# (because they are). Assuming the plaintext is large enough
# and, more importantly, includes repeated blocks of 16-bytes,
# we can safely detect ECB. Of couse this would probably not
# work for a small plaintext.
def ecb_or_cbc(txt):
    # ENCRYPT the given txt using encryption_oracle
    ct = encryption_oracle(txt)
    # DETECT if it is ECB or CBC
    return c8.is_ecb(ct, 1)

def main():
    # RUN some tests
    # There is no way to determine exactly which one is used
    # so let's just run it on the same plaintext a bunch of times
    # and see what the result is.

    # Use the plaintext from challenge 10 since it's long and repeats
    f = open('../../testdata/10.txt')
    ct = f.read()
    key = 'YELLOW SUBMARINE'
    pt = c10.aes_128_cbc_decrypt(c1.base64toascii(ct), key)

    # Count true and false
    tcount = 0
    fcount = 0
    for i in range(50):
        result = ecb_or_cbc(pt)
        if result:
            tcount += 1;
        else:
            fcount += 1;
    print "ECB: " + str(tcount)
    print "CBC: " + str(fcount)
    return

if __name__ == "__main__": main()

#a Challenge 18
## Implement CTR, the stream cipher mode
from Crypto.Cipher import AES
import sys, struct
sys.path.insert(0, '../set1')
import c1, c2

### The given string decrypts to something approximating English
### in CTR mode, which is an AES block cipher mode that turns AES into
### a stream cipher, with the following parameters:
###   key=YELLOW SUBMARINE
###   nonce=0
###   format=64 bit unsigned little endian nonce
###          64 bit little endian block count

### CTR mode is very simple.
### Instead of encrypting the plaintext, CTR mode encrypts a running
### counter, producing a 16-byte block of keystream, which is XOR'd
### against the plaintext.

### CTR mode does not require padding; when you run out of plaintext, you
### just stop XOR'ing keystream and stop generating keystream.

### Decryption is identical to encryption. Generate the same keystream, XOR,
### and recover the plaintext.
### Decrypt the string at the top of this function, then use your CTR
### function to encrypt and decrypt other things.

# Stolen from StackOverflow
def little_endian(num):
    return struct.pack('<Q', num)

def aes_128_ctr(txt, key, nonce = 0):
    num_blocks = (len(txt) / 16) + 1
    keystream = ''
    for i in range(num_blocks):
        val = little_endian(nonce) + little_endian(i)
        keystream += AES.new(key, AES.MODE_ECB).encrypt(val)
    return c2.xorstrs(txt, keystream[:len(txt)])


def main():
    txt = b'L77na/nrFsKvynd6HzOoG7GHTLXsTV'
    txt += b'u9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    pt  = aes_128_ctr(c1.base64toascii(txt), key, 0)
    expected = b'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby '
    assert pt == expected, pt

if __name__ == "__main__" : main()

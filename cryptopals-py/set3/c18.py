# Challenge 18
## Implement CTR, the stream cipher mode
from Crypto.Cipher import AES
import sys, struct
sys.path.insert(0, '../set1')
import c1, c2

# Stolen from StackOverflow
def little_endian(num):
    return struct.pack('<Q', num)

def aes_128_ctr(txt, key, nonce):
    num_blocks = (len(txt) / 16) + 1
    keystream = ''
    for i in range(num_blocks):
        val = little_endian(nonce) + little_endian(i)
        keystream += AES.new(key, AES.MODE_ECB).encrypt(val)
    return c2.xorstrs(txt, keystream[:len(txt)])


def main():
    txt = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = 'YELLOW SUBMARINE'
    pt = aes_128_ctr(c1.base64toascii(txt), key, 0)
    print pt

if __name__ == "__main__" : main()

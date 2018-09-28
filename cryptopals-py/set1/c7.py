# Challenge 7
## AES in ECB mode

from Crypto.Cipher import AES

DEBUG = False

### The base64-encoded content in this file has been encrypted via
### AES-128 in ECB mode under the key
###   "YELLOW SUBMARINE"
### (case-sensitive, without the quotes; exactly 16 characters).
### Decrypt it. You know the key, after all.

## Solves challenge 7 by running aes decrypt
def challenge7():
    f = open('../../testdata/7.txt')
    txt = f.read()
    txt = txt.decode('base64')
    key = 'YELLOW SUBMARINE'
    result = aes_128_ecb_decrypt(txt, key)
    if DEBUG:
        print result

## Uses the AES library function to decrypt
def aes_128_ecb_decrypt(txt, key, IV='\x00'*16):
    return AES.new(key, AES.MODE_ECB).decrypt(txt)

## Uses the AES library function to encrypt
def aes_128_ecb_encrypt(txt, key, IV='\x00'*16):
    return AES.new(key, AES.MODE_ECB).encrypt(txt)

if __name__ == '__main__' : challenge7()

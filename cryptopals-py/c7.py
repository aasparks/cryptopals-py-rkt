# Challenge 7
# AES in ECB mode

from Crypto.Cipher import AES

## Solves challenge 7 by running aes decrypt
def challenge7():
    f = open('7.txt')
    txt = f.read()
    txt = txt.decode('base64')
    key = 'YELLOW SUBMARINE'
    print aes_128_ecb_decrypt(txt, key)

## Uses the AES library function to decrypt
def aes_128_ecb_decrypt(txt, key, IV='\x00'*16):
    return AES.new(key, AES.MODE_ECB).decrypt(txt)

## Uses the AES library function to encrypt
def aes_128_ecb_encrypt(txt, key, IV='\x00'*16):
    return AES.new(key, AES.MODE_ECB).decript(txt)

if __name__ == '__main__' : challenge7()

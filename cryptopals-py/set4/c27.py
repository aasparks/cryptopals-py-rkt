# Challenge 27
## Recover the key from CBC with IV=KEYa
import sys, os
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
sys.path.insert(0, '../set3')
import c2, c6, c9, c10
### Take your code from exercise 16 and modify it so that it uses
### the key for CBC encryption as the IV.
key = os.urandom(16)
prefix = 'comment1=cooking%20MCs;userdata='
suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

def encrypt_userdata(data):
    new = prefix + data.replace(';', '').replace('=', '') + suffix
    new = c9.pkcs7_pad(new)
    return c10.aes_128_cbc_encrypt(new, key, key)

### Applications sometimes use the key as an IV on the auspices that
### both the sender and the receiver have to know the key already, and can
### save some space by using it as both the key and an IV.

### Using the key as an IV is insecure; an attacker that can modify
### ciphertext in flight can get the receiver to decrypt a value
### that will reveal the key.

### The CBC code from exercise 16 encrypts a URL string. Verify each byte
### of the plaintext for ASCII compliance. Noncompliant messages should raise
### an exception or return an error that includes the decrypted plaintext.
def verify_url(data):
    pt = c10.aes_128_cbc_decrypt(data, key, key)
    valid = True

    for c in pt:
        valid &= ord(c) > 31

    return valid, pt

### Use your code to encrypt a message that is at least 3 blocks long:
### AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

### Modify the message to:
### C_1, C_2, C_3 -> C_1, 0, C_1
### Decrypt the message and raise the appropriate error.
### As the attacker, recovering the plaintext from the error, extract the key:
### P'_1 ^ P'_3
def attack_cbc():
    ct = encrypt_userdata('blahblahblah')
    bad_ct = ct[:16] + ('\x00' * 16) + ct[:16]
    valid, pt = verify_url(bad_ct)
    k = c2.xorstrs(c6.get_block(pt, 0), c6.get_block(pt, 2))
    assert k == key

if __name__ == "__main__" : attack_cbc()

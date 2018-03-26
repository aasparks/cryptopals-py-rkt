# Challenge 25
## Break 'random access read/write' AES CTR
import os, sys
sys.path.insert(0, '../set1')
sys.path.insert(0, '../set2')
sys.path.insert(0, '../set3')
import c2, c7, c18

### Back to CTR. Encrypt the recovered plaintext from this file under CTR
### with a random key (unknown to you).
plaintext = open('25.txt').read().decode('base64')
plaintext = c7.aes_128_ecb_decrypt(plaintext, 'YELLOW SUBMARINE')
key = os.urandom(16)
ciphertext = c18.aes_128_ctr(plaintext, key)

### Now write the code that allows you to 'seek' into the ct,
### decrypt, and re-encrypt with different pt. Expose 
### this function as edit(ct, key, offset, newtext)
def edit(ct, key, offset, newtext):
    new_ct = ct[:offset]
    new_ct += c18.aes_128_ctr(('\x00' * offset) + newtext, key)[offset:]
    new_ct += ct[offset+len(newtext):]
    return new_ct


### Imagine the edit function was exposed to attackers by means
### of an API call that didn't reveal the key or the original
### plaintext; the attacker has the ct and controls the offset
### and newtext.
def api_edit(ct, offset, newtext):
    return edit(ct, key, offset, newtext)
### Recover the original plaintext
def main():
    # Check for off by one error
    assert len(ciphertext) == len(api_edit(ciphertext, 5, 'abcde'))
    pt = api_edit(ciphertext, 0, ciphertext) 
    print pt

if __name__ == '__main__' : main()

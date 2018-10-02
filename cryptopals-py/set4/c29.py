# Challenge 29
## Break a SHA-1 keyed MAC using length extension.
import os, sys, math, struct
sys.path.insert(0, '../set1')
import c1, c28

import MYSHA1

### Secret-prefix SHA-1 MACs are trivially breakable.
### The attack on secret-prefix SHA1 relies on the fact
### that you can take the output of SHA-1 and use it as
### a new starting for SHA-1, thus taking an arbitrary
### SHA-1 hash and 'feeding it more data'.

### Since the key precedes the data in secret-prefix,
### any additional data you feed the sHA-1 hash in
### this fassion will appear to have been hashed with
### the secret key.

### To carry out the attack, you'll need to account for the
### fact that SHA-1 is 'padded' with the bit-length of the
### message; your forged message will need to include that
### padding. We call this the 'glue padding'. The final
### message you actually forge will be:
###   SHA1(key || original-message || glue-padding || new-message)
### (where the final padding on the whole constructed message is implied)

### Note that to generate the glue padding, you'll need to know the
### original bit length of the message; the message itself is known
### to the attacker, but the secret key isn't, so you'll need to guess
### at it.

### This sounds more complicated than it is in practice.

### To implement this attack, first write the function that computes
### the MD padding of an arbitrary message and verify that you're
### generating the same padding that your SHA-1 implementation is using.
### This should take you 5-10 minutes

# Finding the glue padding of a message works a lot like pre_process
def glue_padding(message):
    message_len              = len(message)
    message_bit_len          = message_len * 8
    num_blocks               = math.ceil((message_len + 9.0) / 64.0)
    new_len                  = int(num_blocks * 64)
    new_msg                  = bytearray(new_len)
    new_msg[0:message_len+1] = message + chr(0x80)
    postfix                  = struct.pack(b'>Q', message_bit_len)
    new_msg[-len(postfix):]  = postfix
    return new_msg

### Now, take the SHA-1 secret-prefix MAC of the message you want
### to forge -- this is just the SHA-1 hash -- and break it into
### 32-bit SHA-1 registers.
def get_state(message):
    h     = c28.mac_sha1(message).encode('hex')
    new_h = [int(h[i:i+8], 16) for i in range(0, len(h), 8)]
    return new_h


### Modify your SHA-1 implementation so that callers can pass in
### new values for the registers. With the registers 'fixated',
### hash the additional data you want to forge.

### Using this attack, generate a secret-prefix MAC under a secret
### key of the string
### "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

### Forge a variant of this message that ends with ";admin=true"
def forge_message(message, attack):
    new_regs       = get_state(message)
    glue_pad       = glue_padding(('\x00'*16) + message)
    forged_message = glue_pad[16:] + attack
    forged_tag     = MYSHA1.MYSHA1(attack,n_l=len(forged_message)+16, n_h=new_regs).digest()
    return forged_message, forged_tag


# Test that glue padding works as expected
def test_glue_padding():
    test_sha = MYSHA1.MYSHA1(b'abc')
    assert test_sha.message == glue_padding(b'abc')

# Test that we can actually forge a message
def test_forge():
    o_msg        = b'comment1=cooking%20MCs;userdata=foo'
    o_msg        += b';comment2=%20like%20a%20pound%20of%20bacon'
    f_msg, f_tag = forge_message(o_msg, b';admin=true')
    real_tag     = c28.mac_sha1(f_msg)
    assert real_tag == f_tag

if __name__ == "__main__":
    test_glue_padding()
    test_forge()



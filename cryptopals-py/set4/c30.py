# Challenge 30
## Break an MD4 Keyed MAC Using Length Extension

### Second verse, same as the first, but use MD4 instead
### of SHA-1. Having done this attack once against SHA-1,
### the MD4 variant should take much less time; mostly
### just the time you'll spend Googling for an implementation
### of MD4.

# Since I did it for Racket, I'll just implement MD4 myself.
import MD4, os, math, struct

KEY = os.urandom(16)

# MD4 MAC
def mac_md4(message):
    return MD4.MD4(KEY + message).digest()

# Finding the glue padding of a message works a lot like pre_process
def glue_padding(message):
    message_len              = len(message)
    message_bit_len          = message_len * 8
    num_blocks               = math.ceil((message_len + 9.0) / 64.0)
    new_len                  = int(num_blocks * 64)
    new_msg                  = bytearray(new_len)
    new_msg[0:message_len+1] = message + chr(0x80)
    postfix                  = struct.pack(b'<Q', message_bit_len)
    new_msg[-len(postfix):]  = postfix
    return new_msg

# Get the new state to be injected
def get_state(message):
    h     = mac_md4(message)
    # The difference between the solutions is the endianness
    new_h = [struct.unpack(b'<I', h[i:i+4])[0] for i in range(0, len(h), 4)]
    return new_h

### Forge a variant of this message that ends with ";admin=true"
def forge_message(message, attack):
    new_regs       = get_state(message)
    glue_pad       = glue_padding(('\x00'*16) + message)
    forged_message = glue_pad[16:] + attack
    forged_tag     = MD4.MD4(attack,n_l=len(forged_message)+16, new_reg=new_regs).digest()
    return forged_message, forged_tag


# Test that glue padding works as expected
def test_glue_padding():
    test_md4 = MD4.MD4(b'abc')
    assert test_md4.message == glue_padding(b'abc')

# Test that we can actually forge a message
def test_forge():
    o_msg        = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    f_msg, f_tag = forge_message(o_msg, b';admin=true')
    real_tag     = mac_md4(f_msg)
    assert real_tag == f_tag, str(real_tag) + '\n' + str(f_tag)

if __name__ == "__main__":
    test_glue_padding()
    test_forge()

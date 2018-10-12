"""
Challenge 29
Break a SHA-1 keyed MAC using length extension.

Secret-prefix SHA-1 MACs are trivially breakable. The attack on secret-prefix
SHA1 relies on the fact that you can take the output of SHA-1 and use it as
a new starting for SHA-1, thus taking an arbitrary SHA-1 hash and 'feeding it
more data'.

Since the key precedes the data in secret-prefix, any additional data you feed
the sHA-1 hash in this fashion will appear to have been hashed with the secret
key.

To carry out the attack, you'll need to account for the fact that SHA-1 is
'padded' with the bit-length of the message; your forged message will need to
include that padding. We call this the 'glue padding'. The final message you
actually forge will be:
    SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit
length of the message; the message itself is known to the attacker, but the
secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement this attack, first write the function that computes the MD padding
of an arbitrary message and verify that you're generating the same padding that
your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge -- this
is just the SHA-1 hash -- and break it into 32-bit SHA-1 registers.

Modify your SHA-1 implementation so that callers can pass in new values for the
registers. With the registers 'fixated', hash the additional data you want to
forge.

Using this attack, generate a secret-prefix MAC under a secret key of the string
    "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".
"""
import os, sys, math, struct, unittest
sys.path.insert(0, '../set1')
import c1, c28
from MYSHA1 import MYSHA1 as sha1

# Finding the glue padding of a message works a lot like pre_process
def glue_padding(message):
    """
    Figures out the glue padding for the SHA-1 message. Almost identical to
    MYSHA1.pre_process()

    Args:
        message: The message to get the padding for

    Returns:
        The message with the glue padding
    """
    message_len              = len(message)
    message_bit_len          = message_len * 8
    num_blocks               = math.ceil((message_len + 9) / 64)
    new_len                  = int(num_blocks * 64)
    new_msg                  = bytearray(new_len)
    new_msg[0:message_len+1] = message + bytes([0x80])
    postfix                  = struct.pack(b'>Q', message_bit_len)
    new_msg[-len(postfix):]  = postfix
    return new_msg

def get_state(message):
    """
    Gets the SHA-1 state array from the message

    Args:
        message: The message to extract the state from

    Returns:
        List containing the SHA-1 state for injection.
    """
    h     = c1.asciitohex(c28.mac_sha1(message))
    new_h = [int(h[i:i+8], 16) for i in range(0, len(h), 8)]
    return new_h

def forge_message(message, attack):
    """
    Forge's a message with the associated MAC for a SHA-1 MAC

    Args:
        message: The untainted message
        attack: The message to inject using length extension

    Returns:
        The forged message, tag pair for a SHA-1 length extension attack.
    """
    new_regs       = get_state(message)
    glue_pad       = glue_padding((b'\x00'*16) + message)
    forged_message = glue_pad[16:] + attack
    forged_tag     = sha1(attack,n_l=len(forged_message)+16, n_h=new_regs).digest()
    return forged_message, forged_tag

class TestSHA1LengthExt(unittest.TestCase):
    def test_glue_padding(self):
        self.assertEqual(sha1(b'abc').message, glue_padding(b'abc'))

    def test_forge(self):
        o_msg        = b'comment1=cooking%20MCs;userdata=foo'
        o_msg        += b';comment2=%20like%20a%20pound%20of%20bacon'
        f_msg, f_tag = forge_message(o_msg, b';admin=true')
        real_tag     = c28.mac_sha1(f_msg)
        self.assertEqual(f_tag, real_tag)

if __name__ == "__main__":
    unittest.main()



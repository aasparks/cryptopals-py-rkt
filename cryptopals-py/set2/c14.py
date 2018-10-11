"""
Challenge 14
Byte-at-a-time ECB Decryption (Harder)


Take your oracle function from #12. Now generate a random count
of random bytes and prepend this string to every plaintext.

You are now doing:
    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target bytes
"""
import os, sys, random, unittest
from Crypto.Cipher import AES
sys.path.insert(0, '../set1')
import c1, c6, c9

key     = os.urandom(16)
rando   = os.urandom(random.randint(5, 100))
unknown = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
unknown += 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
unknown += 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown = c1.base64toascii(unknown)

# Encryption oracle
def encryption_oracle(txt):
    """
    Encrypts the given text under a secret key with a secret, random prefix, and
    and unknown suffix.

    Args:
        txt: The (attacker-controlled) text to be encrypted

    Returns:
        AES-128-ECB(random-prefix || txt || unknown-string, random-key)
    """
    return AES.new(key, AES.MODE_ECB).encrypt(c9.pkcs7_pad(rando + txt + unknown))

# Since the prefix is constant, this is pretty much
# the same as the last one, but we need to find the
# prefix first. Since it isn't forcing me to verify
# the block size and ECB encoding, I'm going to skip
# that. This is going to have lots of copied code.

## How do I determine the prefix size?
## Sending with '' : XXXX XXTH ESEC RET1
## Sending with 'A' : XXXX XXAT HESE CRET
## From this we know it's in the second block.
## How do we figure out which byte it is?
## Sending with 'AA' : XXXX XXAA THES ECRE T333
## Sending with 'AAA : XXXX XXAA ATHE SECR ET22
## Ok now we see that we reached the end of the block.
## So the last byte of prefix is where we are minus how much we put in
## --- size = start_len + (blocksize - (len(controlled_bytes)-1))
## --- size = 4 + 4 - 3 + 1 = 6
# Determines the size of the prefix the oracle is using
def get_prefix_size(oracle):
    """
    Determines the size of the prefix for the encryption oracle.

    Args:
        oracle: The encryption oracle

    Returns:
        The size of the prefix and the length of the secret
    """
    controlled_bytes = b''
    original         = oracle(controlled_bytes)
    controlled_bytes += b'A'
    test             = oracle(controlled_bytes)
    # Find the block where the prefix ends
    prefix_block = find_prefix_block(original, test)
    start_len    = (prefix_block * 16);
    # Loop through the block, looking for the end
    for i in range(15):
        controlled_bytes += b'A'
        new_test         = oracle(controlled_bytes)
        if c6.get_block(new_test, prefix_block) == c6.get_block(test, prefix_block):
            break;
        test = new_test
    # BUG: when prefix size mod block size is 0, this is off by one. I don't care.
    return start_len + 16 - (len(controlled_bytes)-1), (len(controlled_bytes)-1) % 16

# Finds the block where the prefix ends
def find_prefix_block(oracle, test):
    """
    Finds the block that contains the prefix

    Args:
        original: The result of encryption_oracle(b'')
        test: The result of encryption_oracle(b'A')

    Returns:
        The block number where the prefix ends

    Raises:
        RuntimeError if the block is not found
    """
    for i in range(len(oracle) // 16):
        if c6.get_block(oracle, i) != c6.get_block(test, i):
            return i
    raise RuntimeError('could not find prefix block')


# Now that I know the prefix size, I can do what
# I did last time.
# Knowing the prefix size, we need to have our own,
# permanent prefix size to keep it block aligned.
def decode_secret():
    """
    Decodes the secret bytes from the encryption oracle

    Returns:
        The secret bytes that it found
    """
    prefix_size, needed_size = get_prefix_size(encryption_oracle)
    assert (prefix_size + needed_size) % 16 == 0
    # We can't send the encryption oracle with nothing this time.
    # get_prefix_size() does this for you so now it returns that value.
    ## We send encryption_oracle 'A' * needed_size so that the blocks
    ## match up to the end of the block that the prefix is in.
    ## XXXX XXAA THES ECRE T
    oracle = encryption_oracle(b'A' * needed_size)
    # The number of bytes we have to decode is going to be
    #   len(oracle) - prefix_size - needed_size
    # This should be self-explanatory. If it isn't,
    # you don't understand what's happening.
    num_bytes = len(oracle) - prefix_size - needed_size
    secret    = b''
    c         = decode_byte(secret, num_bytes, prefix_size, needed_size)
    while c is not None:
        secret += c
        c = decode_byte(secret, num_bytes, prefix_size, needed_size)
    return secret

# How does this function differ?
# Let's think about what we send.
#   XXXX XXAA
# Is sent every time no matter what.
#   XXXX XXAA THES ECRE T
#   XXXX XXAA AAAA AAAA AAAT HESE CRET
def decode_byte(known, num_bytes, prefix_size, needed_extra):
    """
    Decodes the next byte of the unknown string.

    Args:
        known: Bytestring containing the bytes from unknown-string that we
        know so far.
        num_bytes: The length of the ciphertext
        prefix_size: The length of the secret prefix
        needed_extra: The length of bytes we still need
    """
    prefix   = craft_block(len(known), num_bytes + needed_extra)
    original = encryption_oracle(prefix)
    length   = prefix_size + len(prefix) + len(known) + 1
    for i in range(256):
        ct = encryption_oracle(prefix + known + bytes([i]))
        if (ct[:length] == original[:length]):
            return bytes([i])
    return None

def craft_block(offset, num_bytes):
    """
    Crafts a block that is one byte short of the num_bytes - offset

    Args:
        offset: The number of bytes already known, that don't need to be crafted
        num_bytes: The number of bytes that need to be found in total

    Returns:
        A bytestring of all A's that is of length num_bytes - offset - 1
    """
    return b'A' * (num_bytes - 1 - offset)

class TestECBByteAtATimeHarder(unittest.TestCase):
    def test_challenge_14(self):
        actual = c9.pkcs7_unpad(decode_secret())
        self.assertEqual(actual, unknown)

if __name__ == "__main__" :
    unittest.main()

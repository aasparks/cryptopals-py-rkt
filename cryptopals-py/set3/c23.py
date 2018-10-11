"""
Challenge 23
Clone an MT19937 RNG from its output

The internal state of MT19937 consists of 624 32-bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting
the state regularly, MT199337 achieves a period of 2**19937, which is BIG.

Each time MT19937 is tapped, an element of its internal state is subjected to
a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write  an 'untemper' function
that takes an MT19937 output and transforms it back into the corresponding
element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in
the temper transform in reverse order. There are two kinds of operations in the
temper transform each applied twice; one is an XOR against a right-shifted
value, and the other is an XOR against a left-shifted value AND'd with a magic
number. So you'll need code to invert the 'right' and 'left' operation.

Once you have 'untemper' working, create a new MT19937 generator, tap it for
624 outputs, untemper each of them to recreate the state of the generator, and
splice that state into a new instance of the MT19937 generator.

The new 'spliced' generator should predict the values of the original.
"""
import c21, unittest

b = 0x9D2C5680
c = 0xEFC60000
s = 7
t = 15
u = 11
l = 18

# Here's where the magic happens
# I need to undo the above function
def untwist(num):
    """
    Untwists a number to recreate the state of MT19937.

    Args:
        num: The number to untwist.

    Returns:
        The value of the state that generated that number.
    """
    value = num
    value = unbitshift_right(value, l)
    value = unbitshift_left(value, t, c)
    value = unbitshift_left(value, s, b)
    value = unbitshift_right(value, u)
    return value

# Unbitshift functions taken from
# https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
def unbitshift_right(value, shift):
    """
    Reverses the right bitshift operation of MT19937.

    Args:
        value: The value after being shifted.
        shift: The amount the original value was shifted by.

    Returns:
        The value before the right bitshift happened.
    """
    i      = 0
    result = 0

    while i * shift < 32:
        part_mask = rlshift((-1 << (32 - shift)), (shift * i))
        part      = value & part_mask
        value     ^= rlshift(part, shift)
        result    |= part
        i         += 1
    return result

def unbitshift_left(value, shift, mask):
    """
    Reverses the left bitshift operation of MT19937.

    Args:
        value: The value after being shifted.
        shift: The amount the original value was shifted by.
        mask: The mask used to shift.

    Returns:
        The value before the left bitshift happened.
    """
    i      = 0
    result = 0

    while i * shift < 32:
        part_mask = rlshift(-1, (32 - shift)) << (shift * i)
        part      = value & part_mask
        value     ^= (part << shift) & mask
        result    |= part
        i         += 1
    return result

# Python does not have a logical right shift built in
# so that's what this does.
def rlshift(value, n):
    """
    Performs a logical right shift.

    Args:
        value: The value to be shifted
        n: The amount to shift by

    Return:
        The logical right shift (value >>> n)
    """
    return (value % 0x100000000) >> n

class TestMTClone(unittest.TestCase):
    def test_challenge_23(self):
        mt = c21.MT19937(234)
        cracked_state = [0] * 624
        # Untwist 624 numbers to get the state of the twister
        for i in range(624):
            cracked_state[i] = untwist(mt.generate_number())
        # Create a new twister and insert the state
        new_mt    = c21.MT19937(0)
        new_mt.mt = cracked_state

        # Check that the next 50 generated numbers are the same
        for i in range(50):
            a = mt.generate_number()
            b = new_mt.generate_number()
            self.assertEqual(a, b)

if __name__ == "__main__" :
    unittest.main()

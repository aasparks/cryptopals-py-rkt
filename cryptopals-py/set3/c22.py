"""
**Challenge 22**

*Crack an MT199337 seed*

Make sure your MT19937 accepts an integer seed value. Test it.

Write a routine that performs the following operations:

* Wait a random number of seconds between 40 and 1000
* Seed the RNG with the current Unix timestamp
* Wait a random number of seconds again
* Return the first number from the RNG

You get the idea. Go get coffee while it runs. Or just simulate the passage
of time, although you're missing some of the fun of this exercise if you do
that.

From the 32-bit RNG output, discover the seed.
"""
import time, unittest
from random import randint
import c21

def bad_seed_mt(testing=False):
    """
    Waits a random amount of time, creates a seed using the current time,
    waits a little longer, then returns the generator.

    Args:
        testing: If testing is true, the function will not sleep, but simulate
        passage of time by subtracting a random number from the current time.

    Returns:
        The MT19937 generator, seeded with the time
    """
    seed = 0

    if testing:
        seed = int(time.time()) - randint(80, 2000)
    else:
        time.sleep(randint(40, 1000))
        seed = int(time.time())
        time.sleep(randint(40, 1000))
    return c21.MT19937(seed)

## From the 32-bit output, discover the seed
def find_seed(num):
    """
    Discovers the seed used by MT199937 to get the number by trying seed values
    from the current time, down to the actual seed.

    Args:
        num: The first num the MT19937 generated.

    Returns:
        The seed value used by the MT19937.
    """
    curr_time = int(time.time())
    while True:
        mt = c21.MT19937(curr_time)
        if mt.generate_number() == num:
            return curr_time
        curr_time -= 1

class TestMT19937(unittest.TestCase):
    def test_challenge_22(self):
        mt    = bad_seed_mt(testing=True)
        num   = mt.generate_number()
        seed  = find_seed(num)
        my_mt = c21.MT19937(seed)
        self.assertEqual(my_mt.generate_number(), num)

        for i in range(50):
            self.assertEqual(my_mt.generate_number(), mt.generate_number())

if __name__ == '__main__' :
    unittest.main()

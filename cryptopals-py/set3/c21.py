# Challenge 21
## Implement the MT19937 Mersenne Twister RNG

# Mersenne Twister class
# Pseudocode from Wikipedia
class MT19937:
    # word size (number of bits)
    w = 32
    # degree of recurrence
    n = 624
    # middle word, an offset used in the recurrence relation
    # defining the series x, 1 <= m < n
    m = 397
    # separation point of one word, or the number of bits
    # of the lower bitmask, 0 <= r <= w-1
    r = 31
    # coefficients of the rational normal form twist matrix
    a = 0x9908B0DF # SUB 16
    # tempering bitmasks
    b = 0x9D2C5680
    c = 0xEFC60000
    s = 7
    t = 15
    u = 11
    d = 0xFFFFFFFF # SUB 16
    l = 18
    f = 1812433253
    # x.i = f x (x.i-1 ^ (x.i-1 >> (w-2))) + i
    def __init__(self, seed):
        self.index = self.n
        self.mt    = [0] * self.n
        self.mt[0] = seed
        for i in range(1, self.n):
            prev = self.mt[i-1]
            prevShifted = prev >> self.w - 2
            self.mt[i] = int32(self.f * (prev ^ prevShifted) + i)

    def generate_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.mt[self.index]
        y = y ^ (y >> self.u)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index = (self.index + 1)
        return int32(y)

    def twist(self):
        first_bit_mask = 0x80000000
        last_bit_mask  = 0x7FFFFFFF
        for i in range(624):
            idx = (i + 1) % 624
            first_i = self.mt[i] & first_bit_mask
            last_i1 = self.mt[idx] & last_bit_mask
            temp = int32(first_i | last_i1)
            if temp % 2 != 0:
                temp = temp >> 1
                temp = temp ^ self.a
            else:
                temp = temp >> 1
            self.mt[i] = self.mt[(i+self.m)%624] ^ temp
        self.index = 0

# Make sure it's only 32 bits
def int32(num):
    return int(num & 0xFFFFFFFF)

# Test vector
def main():
    mt = MT19937(1131464071)
    f  = open('mt_test.txt')

    for line in f:
        expected = line.strip()
        actual   = str(mt.generate_number())
        err = 'Failed. Expected ' + expected
        err += ' got ' + str(actual)
        assert actual == expected, err

if __name__ == "__main__" : main()



# My SHA1 implementation
import os, sys
sys.path.insert(0, '../set1')
import struct, time, math, c1

# DEBUG
DEBUG = False

# rotl
## Circular left rotate function from FIPS 180-4
def rotl(x ,n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

# The following functions define f as a function of t
# during digest, as given in FIPS 180-4
def ch(x, y, z):
    return (x & y) ^ (~x & z)

def parity(x, y, z):
    return x ^ y ^ z

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

# sum32
# add two numbers, mod 32-bits
def sum32(x):
    return sum(x) & 0xffffffff

class MYSHA1:
    # Initialize variables
    def __init__(self, message, n_l=0, n_h=[0x67452301, 0xEFCDAB89, 0x98BADCFE,
                  0x10325476, 0xC3D2E1F0]):
        ## Before computation begins for each of the secure hash
        ## algorithms, the initial hash value, must be set. For
        ## SHA-1, the inital hash value consists of the following
        ## five 32-bit words.
        self.h       = n_h
        self.l       = n_l if n_l != 0 else len(message)
        self.message = message
        self.pre_process()

    # Preprocessing.
    ## Preprocessing shall take place before hash computation
    ## begins. This consists of three steps: padding the message,
    ## M, parsing the padded message into message blocks, and
    ## setting the initial hash value, H(0)
    def pre_process(self):
        global DEBUG
        ## The message, M, shall be padded before hash computation
        ## begins. The purpose of this padding is to ensure that
        ## the padded message is a multiple of 512 bits.
        ## Append a 1 bit to the end of the message, followed by k
        ## zero bits, where k is the smallest, non-negative solution
        ## to the equation
        ##   l + 1 + k === 448 mod 512
        message_bit_len          = self.l * 8
        # NOTE: it took me FOREVER to realize that the l passed in
        # for c29 is used only as a the postfix, and the rest uses
        # len(message)
        message_len              = len(self.message)
        # Instead of calculating the number of zeros, we'll create
        # a buffer of zeros and fill it at the start and end
        num_blocks               = math.ceil((message_len + 9.0) / 64.0)
        new_len                  = int(num_blocks * 64)
        new_msg                  = bytearray(new_len)
        new_msg[0:message_len+1] = self.message + chr(0x80)
        postfix                  = struct.pack(b'>Q', message_bit_len)
        new_msg[-len(postfix):]  = postfix
        self.l                   = new_len
        self.message             = bytes(new_msg)
        ## After the message has been padded, it must be parsed into N
        ## m-bit blocks before the hash computation can begin.
        ## For SHA-1, the padded message is parsed into N 512-bit blocks.
        self.n                   = self.l / 64
        if DEBUG:
            print 'State after preprocessing:'
            print 'MSG: ' + c1.asciitohex(self.message)
            print 'LEN: ' + str(self.l)

    ## SHA-1 may be used to hash a message, M, having a length of l bits.
    ## The algorithm uses
    ##  1) a message schedule of 80 32-bit words
    ##  2) five working variable of 32 bits each
    ##  3) a hash value of 5 32-bit words
    ## The final result of SHA-1 is a 160-bit message digest.
    def digest(self):
        global DEBUG
        for i in range(self.n):
            chunk = self.message[i*64 : (i+1)*64]

            if DEBUG:
                print 'Chunk ' + str(i) + ': ' + chunk.encode('hex')
            ## 1. Prepare the message schedule
            w = [0] * 80
            for j in range(16):
                w[j] = struct.unpack(b'>I', chunk[j*4 : (j+1)*4])[0]
            for j in range(16, 80):
                w[j] = rotl(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

            if DEBUG:
                for j in range(80):
                    print 'w[' + str(j) + ']= ' + format(w[j], '02x')

            ## 2. Initialize the five working variables
            a = self.h[0]
            b = self.h[1]
            c = self.h[2]
            d = self.h[3]
            e = self.h[4]

            ## 3. For t=0 to 79
            for t in range(80):
                if t < 20:
                    f = ch
                    k = 0x5a827999
                elif 20 <= t < 40:
                    f = parity
                    k = 0x6ed9eba1
                elif 40 <= t < 60:
                    f = maj
                    k = 0x8f1bbcdc
                else:
                    f = parity
                    k = 0xca62c1d6

                temp = rotl(a, 5) + f(b, c, d) + e + k + w[t]
                e    = d
                d    = c
                c    = rotl(b, 30)
                b    = a
                a = temp & 0xffffffff

                if DEBUG:
                    print_line(t,a,b,c,d,e)

            ## 4. Computer the i'th intermediate hash value
            # just a wee bit functional since python allows it
            vals = [a, b, c, d, e]
            self.h = map(sum32, zip(self.h, vals))

        # Return the final hash value as bytes
        return b''.join(map(lambda x : struct.pack(">I", x),self.h))

def print_line(i,a,b,c,d,e):
    output_string = 't=' + str(i) + '   '
    output_string += '\t' + format(a, '08x') + '  '
    output_string += '\t' + format(b, '08x') + '  '
    output_string += '\t' + format(c, '08x') + '  '
    output_string += '\t' + format(d, '08x') + '  '
    output_string += '\t' + format(e, '08x')
    print output_string

## Now for testing
# As indicated in the Racket solution as well, I have
# some good test vectors and feel this is a good chance
# to time the tests. So that's what's happening.

# time-test
def time_test(name, f):
    t = time.time() * 1000
    f()
    t2 = time.time() * 1000
    print 'Test ' + name + ' completed in ' + str(t2 - t) + ' ms'

def main():
    time_test("1 block", test1)
    time_test("2 blocks", test2)
    time_test("4 blocks", test3)
    time_test("1 mil a's", test4)


# Test 1
#   abc
def test1():
    result   = c1.asciitohex(MYSHA1(b'abc').digest())
    expected = b'a9993e364706816aba3e25717850c26c9cd0d89d'.upper()
    assert result == expected, 'Expected ' + str(expected) + ' got ' + str(result)

# Test 2
#   abc
def test2():
    result   = MYSHA1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").digest()
    result   = c1.asciitohex(result)
    expected = b'84983E441C3BD26EBAAE4AA1F95129E5E54670F1'
    assert result == expected, 'Expected ' + str(expected) + ' got ' + str(result)

# Test 3
#   abc
def test3():
    result   = MYSHA1(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").digest()
    result   = c1.asciitohex(result)
    expected = b'A49B2446A02C645BF419F995B67091253A04A259'
    assert result == expected, 'Expected ' + str(expected) + ' got ' + str(result)

# Test 4
#   abc
def test4():
    result   = MYSHA1(b'a' * 1000000).digest()
    result   = c1.asciitohex(result)
    expected = b'34AA973CD4C4DAA4F61EEB2BDBAD27316534016F'
    assert result == expected, 'Expected ' + str(expected) + ' got ' + str(result)


if __name__ == '__main__' : main()

"""
**MD4**

My MD4 implementation for Python. Once again, I decided to do it myself.
This is very similar to SHA-1, so it wasn't too bad.
"""
import os, sys, struct, time, math, unittest
sys.path.insert(0, '../set1')
import c1

DEBUG = False

def rotl(x ,n):
    """
    Performs the circular left rotate function from FIPS 180-4.

    Args:
        x: The number to rotate.
        n: The amount to rotate by.

    Returns:
        x left rotated by n.
    """
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def sum32(x):
    """
    Adds an arbitrary amount of numbers and truncates to 32-bits.

    Args:
        x: A list of numbers to add

    Returns:
        The sum of the numbers, truncated to 32-bits.
    """
    return sum(x) & 0xffffffff

class MD4:
    """
    My MD4 implementation.

    Attributes:
        h: The hash value
        l: The message length
        message: The message to be digested
        n: The number of blocks
    """
    # Initialize variables
    def __init__(self, message, n_l=0, new_reg=None):
        ## Before computation begins for each of the secure hash
        ## algorithms, the initial hash value, must be set.
        if new_reg is None:
            new_reg = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.h       = new_reg
        self.l       = n_l if n_l != 0 else len(message)
        self.message = message
        self.pre_process()

    # Preprocessing.
    ## Preprocessing shall take place before hash computation
    ## begins. This consists of three steps: padding the message,
    ## M, parsing the padded message into message blocks, and
    ## setting the initial hash value, H(0)
    def pre_process(self):
        """
        Preproccesses the messages by padding appropriately.
        """
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
        num_blocks               = math.ceil((message_len + 9) / 64)
        new_len                  = int(num_blocks * 64)
        new_msg                  = bytearray(new_len)
        new_msg[0:message_len+1] = self.message + bytes([0x80])
        postfix                  = struct.pack(b'<Q', message_bit_len)
        new_msg[-len(postfix):]  = postfix
        self.l                   = new_len
        self.message             = bytes(new_msg)
        ## After the message has been padded, it must be parsed into N
        ## m-bit blocks before the hash computation can begin.
        self.n                   = self.l // 64
        if DEBUG:
            print('State after preprocessing:')
            print('MSG: ' + c1.asciitohex(self.message))
            print('LEN: ' + str(self.l))

    ## This is where MD4 really differs from SHA-1.
    def digest(self):
        """
        Produces the message digest.

        Returns:
            A bytestring containing the message digest.
        """
        # Process each 16-word block
        for i in range(self.n):
            chunk = self.message[i*64 : (i+1)*64]

            if DEBUG:
                print('Chunk: ' + str(c1.asciitohex(chunk)))

            # Copy block into X
            X = [0] * 16
            for j in range(16):
                val  = chunk[j*4:(j+1)*4]
                X[j] = struct.unpack("<I", val)[0]

            # Save register values
            AA, BB, CC, DD = self.h

            # Round 1
            self.__round1(X)
            if DEBUG:
                print('After round 1: ' + str(map(hex, self.h)))
            self.__round2(X)
            if DEBUG:
                print("After round 2: " + str(map(hex, self.h)))
            self.__round3(X)
            if DEBUG:
                print("After round 3: " + str(map(hex, self.h)))

            vals   = [AA, BB, CC, DD]
            self.h = list(map(sum32, zip(self.h, vals)))

            if DEBUG:
                print('After first block: ' + str(map(hex, self.h)))

        # Return the final hash value as bytes
        result = b''.join(list(map(lambda x : struct.pack("<I", x),self.h)))
        return result

    def __round1_f(self,a,b,c,d,k,s,X):
        num       = sum32([self.h[a], self.__F(self.h[b], self.h[c], self.h[d]), X[k]])
        self.h[a] = rotl(num, s)

    def __round2_f(self, a, b, c, d, k, s, X):
        num       = sum32([self.h[a], self.__G(self.h[b], self.h[c], self.h[d]), X[k], 0x5A827999])
        self.h[a] = rotl(num, s)

    # Round 1
    ## Let [abcd k s] denote the operation:
    ### a = (a + F(b, c, d) + X[k]) <<< s
    def __round1(self, X):
        if DEBUG:
            print(str(X))
            print(str(map(hex, self.h)))
        # For readability
        a,b,c,d = 0,1,2,3
        self.__round1_f(a,b,c,d,0,3,X)
        self.__round1_f(d,a,b,c,1,7,X)
        self.__round1_f(c,d,a,b,2,11,X)
        self.__round1_f(b,c,d,a,3,19,X)
        self.__round1_f(a,b,c,d,4,3,X)
        self.__round1_f(d,a,b,c,5,7,X)
        self.__round1_f(c,d,a,b,6,11,X)
        self.__round1_f(b,c,d,a,7,19,X)
        self.__round1_f(a,b,c,d,8,3,X)
        self.__round1_f(d,a,b,c,9,7,X)
        self.__round1_f(c,d,a,b,10,11,X)
        self.__round1_f(b,c,d,a,11,19,X)
        self.__round1_f(a,b,c,d,12,3,X)
        self.__round1_f(d,a,b,c,13,7,X)
        self.__round1_f(c,d,a,b,14,11,X)
        self.__round1_f(b,c,d,a,15,19,X)
        return

    # Round 2
    ## Let [abcd k s] denote the operation:
    ### a = (a + G(b,c,d) + X[k] + 0x5A827999)
    def __round2(self, X):
        a,b,c,d = 0,1,2,3
        self.__round2_f(a,b,c,d,0,3,X)
        self.__round2_f(d,a,b,c,4,5,X)
        self.__round2_f(c,d,a,b,8,9,X)
        self.__round2_f(b,c,d,a,12,13,X)
        self.__round2_f(a,b,c,d,1,3,X)
        self.__round2_f(d,a,b,c,5,5,X)
        self.__round2_f(c,d,a,b,9,9,X)
        self.__round2_f(b,c,d,a,13,13,X)
        self.__round2_f(a,b,c,d,2,3,X)
        self.__round2_f(d,a,b,c,6,5,X)
        self.__round2_f(c,d,a,b,10,9,X)
        self.__round2_f(b,c,d,a,14,13,X)
        self.__round2_f(a,b,c,d,3,3,X)
        self.__round2_f(d,a,b,c,7,5,X)
        self.__round2_f(c,d,a,b,11,9,X)
        self.__round2_f(b,c,d,a,15,13,X)
        return

    def __round3_f(self, a,b,c,d,k,s, X):
        num       = sum32([self.h[a], self.__H(self.h[b],self.h[c],self.h[d]), X[k], 0x6ED9EBA1])
        self.h[a] = rotl(num, s)
        return

    # Round 3
    ## Let [abcd k s] denote the operation:
    ### a = (a + H(b,c,d) + X[k] + 0x6ED9EBA1) <<< s
    def __round3(self, X):
        a,b,c,d = 0,1,2,3
        self.__round3_f(a,b,c,d,0,3,X)
        self.__round3_f(d,a,b,c,8,9,X)
        self.__round3_f(c,d,a,b,4,11,X)
        self.__round3_f(b,c,d,a,12,15,X)
        self.__round3_f(a,b,c,d,2,3,X)
        self.__round3_f(d,a,b,c,10,9,X)
        self.__round3_f(c,d,a,b,6,11,X)
        self.__round3_f(b,c,d,a,14,15,X)
        self.__round3_f(a,b,c,d,1,3,X)
        self.__round3_f(d,a,b,c,9,9,X)
        self.__round3_f(c,d,a,b,5,11,X)
        self.__round3_f(b,c,d,a,13,15,X)
        self.__round3_f(a,b,c,d,3,3,X)
        self.__round3_f(d,a,b,c,11,9,X)
        self.__round3_f(c,d,a,b,7,11,X)
        self.__round3_f(b,c,d,a,15,15,X)
        return

    # The following functions define f as a function of t
    # during digest, as given in FIPS 180-4
    def __F(self, x, y, z):
        return (x & y) | (~x & z)

    def __G(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def __H(self, x, y, z):
        return x ^ y ^ z

class TestMD4(unittest.TestCase):
    # 'abc'
    def test1(self):
        result   = c1.asciitohex(MD4(b'abc').digest())
        expected = b'a448017aaf21d8525fc10ae87aa6729d'.upper()
        self.assertEqual(result, expected)

    # 2 blocks
    def test2(self):
        msg = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        result   = MD4(msg).digest()
        result   = c1.asciitohex(result)
        expected = b'043f8582f241db351ce627e153e7f0e4'.upper()
        self.assertEqual(result, expected)

    # empty
    def test3(self):
        msg = b""
        result   = MD4(msg).digest()
        result   = c1.asciitohex(result)
        expected = b'31d6cfe0d16ae931b73c59d7e0c089c0'.upper()
        self.assertEqual(result, expected)

    # 1 million A's
    def test4(self):
        result   = MD4(b'A' * 1000000).digest()
        result   = c1.asciitohex(result)
        expected = b'a13f9ee75c400d8e6837bd724fb92d66'.upper()
        self.assertEqual(result, expected)

if __name__ == "__main__" :
    unittest.main()



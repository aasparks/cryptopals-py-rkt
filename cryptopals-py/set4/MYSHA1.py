# My SHA1 implementation
import struct
## Screw finding one online. Let's just do it
## from the pseudocode.

# lrot function
def lrot(x ,n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

class MYSHA1:
    # Initialize variables
    def __init__(self, message):
        ## Before computation begins for each of the secure hash
        ## algorithms, the initial hash value, must be set. For
        ## SHA-1, the inital hash value consists of the following
        ## five 32-bit words.
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE,
                  0x10325476, 0xC3D2E1F0]
        self.l = len(message) * 8
        self.message = message
        self.pre_process()

    # Preprocessing.
    ## Preprocessing shall take place before hash computation
    ## begins. This consists of three steps: padding the message,
    ## M, parsing the padded message into message blocks, and
    ## setting the initial hash value, H(0)
    def pre_process(self):
        ## The message, M, shall be padded before hash computation
        ## begins. The purpose of this padding is to ensure that 
        ## the padded message is a multiple of 512 bits.
        ## Append a 1 bit to the end of the message, followed by k
        ## zero bits, where k is the smallest, non-negative solution
        ## to the equation 
        ##   l + 1 + k === 448 mod 512
        message_len = len(self.message)
        message_bit_len = message_len * 8
        self.message += chr(0x80)
        self.message += b'\x00' * ((56 - (message_len + 1) % 64) % 64)
        self.message += struct.pack(b'>Q', message_bit_len)
        self.l = len(self.message) * 8
        ## After the message has been padded, it must be parsed into N
        ## m-bit blocks before the hash computation can begin.
        ## For SHA-1, the padded message is parsed into N 512-bit blocks.
        self.n = self.l / 512
        self.m = [b''] * self.n

        for i in range(self.n):
            self.m[i] = self.message[i * 512 : (i+1) * 512]
    ## SHA-1 may be used to hash a message, M, having a length of l bits.
    ## The algorithm uses 
    ##  1) a message schedule of 80 32-bit words
    ##  2) five working variable of 32 bits each
    ##  3) a hash value of 5 32-bit words
    ## The final result of SHA-1 is a 160-bit message digest.
    def digest(self):
        for i in range(self.n):
            chunk = self.message[i * 512 : (i + 1 ) * 512]
            #print 'Chunk is ' + chunk.encode('hex')
            ## 1. Prepare the message schedule
            w = [b''] * 80
            for i in range(16):
                w[i] = struct.unpack(b'>I', chunk[i * 4 : (i + 1) * 4])[0]
            for i in range(16, 80):
                w[i] = lrot(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)


            #for i in range(80):
            #    print 'w[' + str(i) + ']= '+ format(w[i], '02x')
            ## 2. Initialize the five working variables
            a = self.h[0]
            b = self.h[1]
            c = self.h[2]
            d = self.h[3]
            e = self.h[4]

            ## 3. For t=0 to 79
            for i in range(80):
                if i < 20:
                    f = d ^ (b & (c ^ d))
                    k = 0x5a827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ed9eba1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) |  (c & d)
                    k = 0x8f1bbcdc
                else:
                    f = b ^ c ^ d
                    k = 0xca62c1d6

                temp = lrot(a, 5) + f + e + k + w[i]
                e = d
                d = c
                c = lrot(b, 30)
                b = a
                a = temp & 0xffffffff
                #print_line(i,a,b,c,d,e)

            ## 4. Computer the i'th intermediate hash value
            self.h[0] = (self.h[0] + a) & 0xffffffff
            self.h[1] = (self.h[1] + b) & 0xffffffff
            self.h[2] = (self.h[2] + c) & 0xffffffff
            self.h[3] = (self.h[3] + d) & 0xffffffff
            self.h[4] = (self.h[4] + e) & 0xffffffff
            return b''.join(map(lambda x : struct.pack(">I", x),self.h))

def print_line(i,a,b,c,d,e):
    output_string = 't=' + str(i) + '\n'
    output_string += '\t' + format(a, '08x') + '\n' 
    output_string += '\t' + format(b, '08x') + '\n'
    output_string += '\t' + format(c, '08x') + '\n' 
    output_string += '\t' + format(d, '08x') + '\n'
    output_string += '\t' + format(e, '08x')
    print output_string

## Now for testing
def main():
    smoke_test()
    test_vectors()

def smoke_test():
    blah = MYSHA1(b'yo mama').digest()
    return

def test_vectors():
    # Test vector 
    result = MYSHA1(b'abc').digest()
    print result.encode('hex')
    return


if __name__ == '__main__' : main()

# Challenge 2
## Fixed XOR
import c1

### Write a function that takes two equal-length buffers and produces
### their XOR combination.

### If your function works properly, then when you feed it the string:
###  1c0111001f010100061a024b53535009181c
### ...after hex decoding, and when XOR'd against:
###  686974207468652062756c6c277320657965
### ...should produce:
###  746865206b696420646f6e277420706c6179

# XOR two strings
def xorstrs(str1, str2):
    assert (len(str1) == len(str2)) # must be equal length
    out = ''
    for (c, k) in zip(str1, str2): # i love zip
        out += chr(ord(c) ^ ord(k)) # xor values, convert to char
    return out

# Challenge 2 solution
def main():
    str1   = c1.hextoascii('1c0111001f010100061a024b53535009181c')
    str2   = c1.hextoascii('686974207468652062756c6c277320657965')
    result = xorstrs(str1, str2)
    assert c1.asciitohex(result) == '746865206b696420646f6e277420706c6179'.upper()

if __name__ == "__main__" : main()

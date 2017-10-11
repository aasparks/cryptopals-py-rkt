# Challenge 2
## Fixed XOR
### Easy peasy
import c1

# XOR two strings
def xorstrs(str1, str2):
    assert (len(str1) == len(str2)) # must be equal length
    out = ''
    for (c, k) in zip(str1, str2): # i love zip
        out += chr(ord(c) ^ ord(k)) # xor values, convert to char
    return out

# Challenge 2 solution
def main():
    str1 = c1.hextoascii('1c0111001f010100061a024b53535009181c')
    str2 = c1.hextoascii('686974207468652062756c6c277320657965')
    result = xorstrs(str1, str2)
    assert c1.asciitohex(result) == '746865206b696420646f6e277420706c6179'.upper()
    print 'pass'

if __name__ == "__main__" : main()

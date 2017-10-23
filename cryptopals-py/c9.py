# Challenge 9
## Implement PKCS7 padding
def pkcs7_pad(txt, n=16):
    num = n - (len(txt) % n)
    return txt + chr(num) * num

# My own tests
def test():
    str1 = "Spongebob Squarepants"
    str2 = pkcs7_pad(str1, 16)
    str3 = pkcs7_pad(str1, 4)
    assert str2 == str1 + "\x0b" * 11
    assert str3 == str1 + "\x03" * 3

# Try the challenge 9 test
def main():
    test()
    str1 = "YELLOW SUBMARINE"
    str2 = pkcs7_pad(str1, 20)
    assert str2 == str1 + "\x04\x04\x04\x04"
    print 'pass'

if __name__ == "__main__" : main()

# Challenge 9
## Implement PKCS7 padding
### Easy peasy

# Pads text according to pkcs7 standard.
# Also accepts optional block size
def pkcs7_pad(txt, n=16):
    num = n - (len(txt) % n)
    return txt + chr(num) * num

def pkcs7_unpad(txt, n=16):
    idx = len(txt) - 1
    num_pads = ord(txt[-1])
    if num_pads > n:
        return txt
    for i in range(num_pads):
        assert txt[idx] == chr(num_pads), 'padding error'
        idx -= 1
    return txt[:idx+1]

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

if __name__ == "__main__" : main()

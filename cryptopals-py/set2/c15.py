# Challenge 15
## PKCS7 Padding Validation

# Easy peasy lemon sequeezy
# I already did this for challenge 9
import c9
import unittest

def main():
    expected = 'ICE ICE BABY'
    assert c9.pkcs7_unpad('ICE ICE BABY\x04\x04\x04\x04') == expected
    exception_caught = False
    try:
        c9.pkcs7_unpad('ICE ICE BABY\x05\x05\x05\x05')
    except:
        exception_caught = True
    assert exception_caught
    exception_caught = False
    try:
        c9.pkcs7_unpad('ICE ICE BABY\x01\x02\x03\x04')
    except:
        exception_caught = True
    assert exception_caught

if __name__ == '__main__': main()

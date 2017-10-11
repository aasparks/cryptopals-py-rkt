# Convert hex to base64
## This one is easy. It's a library function.
import base64

## Let's just go ahead and provide all the conversion functions.

# Convert hex to ascii
def hextoascii(string):
    return base64.b16decode(string.upper())

# Encode ascii string in hex
def asciitohex(string):
    return base64.b16encode(string)

# Encode from hex to base64
def hextobase64(string):
    return base64.b64encode(hextoascii(string))

# Encode from base64 to hex
def base64tohex(string):
    return asciitohex(base64.b64decode(string))

# Encode ascii to base64
def asciitobase64(string):
    return base64.b64encode(string)

# Decode base64 to ascii
def base64toascii(string):
    return base64.b64decode(string)

# Test all the functions
def test():
    asc = 'Who lives in a pineapple under the sea?'
    hx  = '57686f206c6976657320696e20612070696e656170706c6520756e64657220746865207365613f'
    b64 = b'V2hvIGxpdmVzIGluIGEgcGluZWFwcGxlIHVuZGVyIHRoZSBzZWE/'
    assert hextoascii(hx)     == asc
    assert asciitohex(asc)    == hx.upper()
    assert hextobase64(hx)    == b64
    assert base64tohex(b64)   == hx.upper()
    assert asciitobase64(asc) == b64
    assert base64toascii(b64) == asc


## Now for the solution to the challenge
def main():
    test()
    hxstr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 
    b64str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert hextobase64(hxstr) == b64str
    print ('pass')

if __name__ == "__main__" : main()

# Challenge 31
## Implement and Break HMAC-SHA1 with an Artificial Timing Leak
import sys, os
sys.path.insert(0, '../set1')
import c1, MYSHA1, c2
import web, time

DEBUG = True
DELAY = 0.001

### The pseudocode on Wikipedia should be enough. HMAC is very easy.

# hmac using sha1
def hmac_sha1(key, message):
    # If the key is longer than the blocksize,
    # then truncate it by hashing it
    if (len(key) > 64):
        key = MYSHA1.MYSHA1(key).digest()

    # If the key is shorter than blocksize,
    # pad with 0s
    if (len(key) < 64):
        key = key + (b'\x00' * (64 - len(key)))

    o_pad = c2.xorstrs(key, b'\x5c'*64)
    i_pad = c2.xorstrs(key, b'\x36'*64)
    i_msg = i_pad + bytearray(message, 'utf-8')
    o_msg = o_pad + MYSHA1.MYSHA1(i_msg).digest()
    return MYSHA1.MYSHA1(o_msg).digest()

def insecure_compare(str1, str2):
    print c1.asciitohex(str1)
    print c1.asciitohex(str2)
    result = True
    if len(str1) != len(str2):
        return False
    for i in range(len(str1)):
        result &= str1[i] == str2[i]
        if result:
            time.sleep(DELAY)
        else:
            return result
    return result

### Using the web framework of your choosing, write a tiny application that
### has a URL that takes a "file" argument and a "signature" argument, like so:
###  http://localhost:9000/test?file=foo&signature=bar
urls = ('/', 'index')
key = os.urandom(16)

class index:
    def GET(self):
        user_data = web.input(file='', signature='')

        if user_data.file == "" or user_data.signature == "":
            return 500

        expected = hmac_sha1(key, user_data.file)
        actual   = c1.hextoascii(user_data.signature)
        if insecure_compare(expected, actual):
            return 200
        else:
            return 500


def test_hmac():
    expected = b"b617318655057264e28bc0b6fb378c8ef146be00".upper()
    actual = c1.asciitohex(hmac_sha1(b'\x0b'*20, b'Hi There'))
    assert expected == actual, str(actual)


if __name__ == "__main__":
    test_hmac();
    app = web.application(urls, globals())
    app.run()
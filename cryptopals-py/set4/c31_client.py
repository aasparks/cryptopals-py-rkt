"""
Challenge 31 - CLIENT
Implement and Break HMAC-SHA1 with an Artificial Timing Leak

The pseudocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing, write a tiny application that
has a URL that takes a "file" argument and a "signature" argument, like so:
    http://localhost:9000/test?file=foo&signature=bar

Have the server generate an HMAC key, and then verify that the signature on
incoming requests is valid for 'file', using the '==' operator to compare the
valid MAC for a file with the signature parameter (in other words, verify the
HMAC the way any normal programmer would verify it).

Write a function, call it 'insecure_compare', that implements the == operation
by doing byte-at-a-time comparisons with early exit (ie, return false at the
first non-matching byte).

In the loop for 'insecure_compare', add a 50ms sleep (sleep 50ms after each byte)

Use your 'insecure_compare' function to verify the HMACs on incoming requests,
and test that the whole contraption works. Return a 500 if the MAC is invalid,
and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the
valid MAC for any file.
"""
import sys, os, time, requests, threading, unittest
sys.path.insert(0, '../set1')
import c1, c31_server

DELAY = 0.03
DEBUG = True

def time_request(file, mac):
    """
    Calculates how long it takes for a request to go through.

    Args:
        file: The file name
        mac: The signature for the file name

    Returns:
        The time it takes for a request to go through.
    """
    start = time.time()
    url   = b'http://localhost:8080/?file='
    r     = requests.get(url + file + b'&signature=' + mac)
    end   = time.time()
    return end - start

# Debug print the time and number
def __print_time_val(i, t):
    print('t[' + str(i) + ']: ' + hex(i) + ' | ' + str(t))

def timing_attack(file):
    """
    Executes the timing attack.

    Args:
        file: The name of the file to attack

    Returns:
        The cracked HMAC value.
    """
    known = b''

    for i in range(20):
        known += crack_next_byte(known, file)
        if DEBUG:
            print(c1.asciitohex(known))

    return known

# Finds the next byte by taking the request that meets
# the expected delay time
def crack_next_byte(known, file):
    """
    Gets the next byte of the HMAC.

    Args:
        known: The known bytes so far
        file: The name of the file

    Returns:
        The next of the HMAC
    """
    expected_delay = DELAY * len(known)
    expected_delay += DELAY * 0.75

    for i in range(5):
        time_request(file, c1.asciitohex(b'abnsbsuoabna'))

    for i in range(256):
        mac = known + bytes([i]) + bytes([0] * (19 - len(known)))
        t   = time_request(file, c1.asciitohex(mac))

        if DEBUG:
            __print_time_val(i, t)

        if t >= expected_delay:
            return bytes([i])

    raise Exception('unexpected')

class Test31(unittest.TestCase):
    def test_challenge_31(self):
        file = b'secret.txt'
        #expected = c31_server.run_server(file)
        #time.sleep(5)
        actual = timing_attack(file)
        #self.assertEqual(c1.asciitohex(actual), expected)

if __name__ ==  '__main__':
    unittest.main()


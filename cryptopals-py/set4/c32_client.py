"""
**Challenge 32- CLIENT**

*Implement and Break HMAC-SHA1 with an Artificial Timing Leak*

Reduce the sleep in your "insecure_compare" until your previous solution breaks.
(Try 5ms to start)

Now break it again.
"""
import sys, os
sys.path.insert(0, '../set1')
import time, requests, c1

# The c31 solution made it all the way down to 15ms and broke at 10ms.
# Much better than the Racket solution.

# This solution works for 1ms!!!
# This may not be the case for slower machines or slower operating
# systems (cough cough Windoze), but that is pretty cool. One can see
# how the timing attack is effective in the real world.

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

# Do the actual timing attack
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

    return c1.asciitohex(known)

# Finds the next byte by taking the request that meets
# the expected delay time
def crack_next_byte(known, file):
    """
    Gets the next byte of the HMAC by sending every byte 5 times and taking
    an average.

    Args:
        known: The known bytes so far
        file: The name of the file

    Returns:
        The next byte of the HMAC
    """
    avgs = dict().fromkeys(range(256), 0)

    # To get this just right, we'll do multiple attempts for each byte
    # and take the average. If the average is within range, we take it.
    for a in range(5):
        for i in range(256):
            mac = known + bytes([i]) + bytes([0] * (19 - len(known)))
            t   = time_request(file, c1.asciitohex(mac))
            avgs.update({i : avgs.get(i) + t})

    maxAvg = -1
    maxI   = -1
    for i in range(256):
        avgs.update({i : avgs.get(i) / 5.0})
        if DEBUG:
            __print_time_val(i, t)

        # Instead of breaking when we find the expected-delay,
        # we're just going to take the one with the highest avergae.
        if avgs.get(i) > maxAvg:
            maxAvg = avgs.get(i)
            maxI   = i

    return bytes([maxI])

if __name__ ==  '__main__':
    print(timing_attack(b'secret.txt'))


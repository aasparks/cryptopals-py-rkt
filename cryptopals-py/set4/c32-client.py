import sys, os
sys.path.insert(0, '../set1')
import time, requests, c1

# The c31 solution made it all the way down to 15ms and broke at 10ms.
# Much better than the Racket solution.

# This solution works for 1ms!!!
# This may not be the case for slower machines or slower operating
# systems (cough cough Windoze), but that is pretty cool. One can see
# how the timing attack is effective in the real world.

DELAY = 0.001
DEBUG = True

# Determines how long it takes for a request to complete
def time_request(file, mac):
    start = time.time()
    url   = 'http://localhost:8080/?file='
    r     = requests.get(url + file + '&signature=' + mac)
    end   = time.time()
    return end - start

# Determines if a mac is correct
def try_valid(q, mac):
    r = requests.get('http://localhost:8080/?q=' + q + '&mac=' + mac)
    return r.text.find('Correct!') > -1

# Debug print the time and number
def print_time_val(i, t):
    print 't[' + str(i) + ']: ' + chr(i).encode('hex') + ' | ' + str(t)


# Do the actual timing attack
def timing_attack():
    known = b''
    file  = b'secret.txt'

    for i in range(20):
        known += crack_next_byte(known, file)
        if DEBUG:
            print str(c1.asciitohex(known))

    print c1.asciitohex(known)

# Finds the next byte by taking the request that meets
# the expected delay time
def crack_next_byte(known, file):
    avgs = dict().fromkeys(range(256), 0)

    # To get this just right, we'll do multiple attempts for each byte
    # and take the average. If the average is within range, we take it.
    for a in range(5):
        for i in range(256):
            mac = known + chr(i) + chr(0) * (19 - len(known))
            t   = time_request(str(file), str(c1.asciitohex(mac)))
            avgs.update({i : avgs.get(i) + t})

    maxAvg = -1
    maxI   = -1
    for i in range(256):
        avgs.update({i : avgs.get(i) / 5.0})
        if DEBUG:
            print_time_val(i, t)

        # Instead of breaking when we find the expected-delay,
        # we're just going to take the one with the highest avergae.
        if avgs.get(i) > maxAvg:
            maxAvg = avgs.get(i)
            maxI   = i

    return chr(maxI)
    raise Exception('unexpected')


if __name__ ==  '__main__':
    timing_attack()


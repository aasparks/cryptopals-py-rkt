import sys, os
sys.path.insert(0, '../set1')
import time, requests, c1

DELAY = 0.05
DEBUG = False

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
    file = b'secret.txt'

    for i in range(20):
        known += crack_next_byte(known, file)
        if DEBUG:
            print str(c1.asciitohex(known))

    print c1.asciitohex(known)

# Finds the next byte by taking the request that meets
# the expected delay time
def crack_next_byte(known, file):
    expected_delay = DELAY * len(known)
    expected_delay += DELAY * 0.75

    for i in range(256):
        mac = known + chr(i) + chr(0) * (19 - len(known))
        t = time_request(str(file), str(c1.asciitohex(mac)))

        if DEBUG:
            print_time_val(i, t)

        if t >= expected_delay:
            return chr(i)

    raise Exception('unexpected')


if __name__ ==  '__main__':
    timing_attack()


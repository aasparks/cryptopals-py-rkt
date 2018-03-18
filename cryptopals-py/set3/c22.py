# Challenge 22
## Crack an MT199337 seed
import time
from random import randint
import c21
### Make sure your MT19937 accepts an integer seed
### value. Test it.

## Write a routine that performs the following operations:
## - Wait a random number of seconds between 40 and 1000
## - Seed the RNG with the current Unix timestamp
## - Wait a random number of seconds again
## - Return the first number from the RNG
def bad_seed_rand():
    time.sleep(randint(40, 1000))
    seed = int(time.time())
    #print 'Using seed ' + str(seed)
    mt = c21.MT19937(seed)
    time.sleep(randint(40, 1000))
    return mt.generate_number()

## From the 32-bit output, discover the seed
def main():
    num = bad_seed_rand()
    curr_time = int(time.time())
    done = False
    while not done:
        mt = c21.MT19937(curr_time)
        if mt.generate_number() == num:
            print 'Seed: ' + str(curr_time)
            done = True
        curr_time -= 1

if __name__ == '__main__' : main()

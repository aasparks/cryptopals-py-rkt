# Challenge 5
## Implement repeating-key XOR
import c1
import c2
import c3
import c4

# Extend a key to size n
def key_extend(key, n):
    diff = n / len(key)
    if diff > 0:
        key = key * (diff + 1)
    return key[0:n]

# Repeating key works the same so all we needed
# was the above function
def repeating_key_xor(txt, key):
    return c2.xorstrs(txt, key_extend(key, len(txt)))

def test():
    key = key_extend('ICE', 6)
    assert key == 'ICEICE'
    key = key_extend('ICE', 5)
    assert key == 'ICEIC'
    key = key_extend('ICE', 15)
    assert key == 'ICEICEICEICEICE'

# Solution to the challenge
def main():
    test()
    pt = 'Burning \'em, if you ain\'t quick and nimble\n'
    pt += 'I go crazy when I hear a cymbal'
    ct = repeating_key_xor(pt, 'ICE')
    ans = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
    ans += 'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    assert c1.asciitohex(ct) == ans.upper()
    print 'pass'

if __name__ == '__main__' : main()

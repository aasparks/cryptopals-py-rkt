# Cryptopals in Python and Racket

I like crypto and I like Racket. Why not combine them? This is my experiment in doing crypto with a functional language. While I'm at it, I may as well finish doing the challenges in Python, since I've already done some. The idea here is to make imperative solutions with Python, and then attempt to use more functional tactics in Racket (i.e. map, apply, lambda, recursion). Let's see how the solutions vary.

## TODO:
* Compile most-used functions into 'util' files and use that way.
* Convert Python solutions to Python3.
* Rewrite ugly functions to be more elegant.
* Try to optimize the challenges are slow in Racket
  * Challenge 4 (possibly 3 as well)
  * Challenge 12 (possibly the AES implementation as well)
  * Challenge 14
* See if the AES implementation can be improved

## Challenges

### Set 1 - Basics :heavy_check_mark:

#### 1. Convert hex to base64 - :ballot_box_with_check:

Nothing special here. These functions are used in pretty much every exercise
after this. Both languages had these functions built in, though I did
originally write them manually in Racket. They were large and ugly functions
so I decided to stick to the library functions.

#### 2. Fixed XOR - :ballot_box_with_check:

Very easy in both languages.

<span style="color:green">Python has a great function
called ```zip``` which I love dearly and made the solution more elegant.</span>

<span style="color:red">Racket's ```map``` function actually works just like ```zip```, and
handled error checking to make for an even more elegant solution.</span>

#### 3. Single-byte XOR Cipher - :ballot_box_with_check:

Using frequency analysis, this problem is not too difficult. The hard part
is getting a good scoring function.

#### 4. Detect Single-character XOR - :ballot_box_with_check:

Running challenge 3 on every line of the file gets you to the solution
and the plaintext very quickly. However, the Racket solution is much, much
slower.

#### 5. Implement Repeating-key XOR - :ballot_box_with_check:

#### 6. Break Repeating-key XOR - :ballot_box_with_check:

#### 7. AES in ECB Mode - :ballot_box_with_check:

<span style="color:green">Python (obviously) had a library function for AES-128.
</span>

<span style="color:red">Racket did not have a library function so I implemented it
    myself. I may go back and implement it in Python just for fun.

#### 8. Detect AES in ECB Mode - :ballot_box_with_check:

### Set 2 - Block Crypto :heavy_check_mark:

#### 9. Implement PKCS#7 Padding - :ballot_box_with_check:

#### 10. Implement CBC Mode - :ballot_box_with_check:

#### 11. An ECB/CBC Detection Oracle - :ballot_box_with_check:

#### 12. Byte-at-a-time ECB Decryption (Simple) - :ballot_box_with_check:

The first really interesting challenge in the set.

<span style="color:red">The Racket solution is incredibly slow while the
 Python solution is almost immediate. Not sure why.</span>

#### 13. ECB Cut-and-paste - :ballot_box_with_check:

#### 14. Byte-at-a-time ECB Decryption (Harder) - :ballot_box_with_check:

The python solution to this one is much cleaner and way, way faster.

#### 15. PKCS#7 Padding Validation - :ballot_box_with_check:

I did this one with challenge 9. I don't understand why the separated
the two functions.

#### 16. CBC Bitflipping Attacks - :ballot_box_with_check:

### Set 3 - Block & Stream Crypto :x:

#### 17. The CBC Padding Oracle - :ballot_box_with_check:

#### 18. Implement CTR, The Stream Cipher Mode - :ballot_box_with_check:

#### 19. Break Fixed-Nonce CTR Mode Using Substitutions - :black_square_button:

#### 20. Break Fixed-Nonce CTR Statistically - :black_square_button:

#### 21. Implement the MT19937 Mersenne Twister RNG - :ballot_box_with_check:

#### 22. Crack an MT19937 Seed - :ballot_box_with_check:

#### 23. Clone an MT19937 RNG from Its Output - :ballot_box_with_check:

#### 24. Create the MT19937 Stream Cipher and Break It - :ballot_box_with_check:

### Set 4 - Stream Crypto and Randomness :heavy_check_mark:

#### 25. Break "Random Access Read/Write" AES CTR - :ballot_box_with_check:

#### 26. CTR Bitflipping - :ballot_box_with_check:

#### 27. Recover the Key from CBC with IV=Key - :ballot_box_with_check:

#### 28. Implement a SHA-1 Keyed MAC - :ballot_box_with_check:

#### 29. Break a SHA-1 Keyed MAC Using Length Extension - :ballot_box_with_check:

#### 30. Break an MD4 Keyed MAC Using Length Extension - :ballot_box_with_check:

#### 31. Implement and Break HMAC-SHA1 with an Artificial Timing Leak - :ballot_box_with_check:

#### 32. Break HMAC-SHA1 with a Slightly Less Artificial Timing Leak - :ballot_box_with_check:

### Set 5 - Diffie-Hellman and Friends :x:

#### 33. Implement Diffie-Hellman :black_square_button:

#### 34. Implement a MITM Key-Fixing Attack on Diffie-Hellman with Parameter Injection :black_square_button:

#### 35. Implement DH with Negotiated Groups, and Break with Malicious 'g' Parameters :black_square_button:

#### 36. Implement Secure Remote Password (SRP) :black_square_button:

#### 37. Break SRP with a Zero Key :black_square_button:

#### 38. Offline Dictionary Attack on Simplified SRP :black_square_button:

#### 39. Implement RSA :black_square_button:

#### 40. Implement an E=3 RSA Broadcast Attack :black_square_button:

### Set 6 - RSA and DSA :x:

#### 41. Implement Unpadded Message Recovery Oracle :black_square_button:

#### 42. Bleichenbacher's e=3 RSA Attack :black_square_button:

#### 43. DSA Key Recovery from Nonce :black_square_button:

#### 44. DSA Nonce Recovery from Repeated Nonce :black_square_button:

#### 45. DSA Parameter Tampering :black_square_button:

#### 46. RSA Parity Oracle

#### 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case) :black_square_button:

#### 48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case) :black_square_button:

### Set 7 - Hashes :x:

#### 49. CBC-MAC Message Forgery :black_square_button:

#### 50. Hashing with CBC-MAC :black_square_button:

#### 51. Compression Ratio Side-Channel Attacks :black_square_button:

#### 52 Iterated Hash Function Multicollisions :black_square_button:

#### 53. Kelsey and Schneier's Expandable Messages :black_square_button:

#### 54. Kelsey and Kohno's Nostradamus Attack :black_square_button:

#### 55. MD4 Collisions :black_square_button:

#### 56. RC4 Single-Byte Biases :black_square_button:

### Set 8 - Abstract Algebra :x:

#### 57. Diffie-Hellman Revisited: Small Subgroup Confinement :black_square_button:

#### 58. Pollard's Method for Catching Kangaroos :black_square_button:

#### 59. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks :black_square_button:

#### 60. Single-Coordinate Ladders and Insecure Twists :black_square_button:

#### 61. Duplicate-Signature Key Selection in ECDSA (and RSA) :black_square_button:

#### 62. Key-Recovery Attacks on ECDSA with Biased Nonces :black_square_button:

#### 63. Key-Recovery Attacks on GCM with Repeated Nonces :black_square_button:

#### 64. Key-Recovery Attacks on GCM with a Truncated MAC :black_square_button:
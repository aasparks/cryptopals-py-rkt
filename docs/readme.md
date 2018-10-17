# Cryptopals in Python and Racket

I like crypto and I like Racket. Why not combine them? This is my experiment in
doing crypto with a functional language. While I'm at it, I may as well finish
doing the challenges in Python, since I've already done some. The idea here is
to make imperative solutions with Python, and then attempt to use more
functional tactics in Racket (i.e. map, apply, lambda, recursion).
I also want to use this opportunity to master both languages. This includes
writing the documentation, following the Google coding standard, and writing
good unit tests for each challenge.
Let's see how the solutions vary.

# Documentation

To view the documentation for each language, try the links below. I created the
documentation using the official tools for each language. <span style="color:green">
For Python, the tool is Sphinx to parse the docstrings in the source. </span>
<span style="color:red">For Racket, the tool is Scribl, which is all built into
DrRacket.</span> I've used DrRacket tools before, so it was very easy. Sphinx
has quite the learning curve but is a very powerful tool.

[Python](py/html/index.html)
[~~Racket~~](rkt/manual.html)


## Midterm Retrospective

At the half-way point, I have decided to go back through the challenges and
rewrite A LOT. When I started, I barely knew any Python at all. Through these
challenges I have learned a lot. I've learned better, more efficient ways
to solve certain problems, especially in the beginning. The code (and comments)
I have written can be greatly improved. I'd also like to take this time to go
back and work on official documentation for both languages. I've compiled a
to-do list below of issues I found by skimming the code for all the challenges
so far.

### TODO:
* Compile most-used functions into 'util' files and use that way.
* Try to optimize the challenges that are slow in Racket
  * Challenge 12
  * Challenge 14
  * Challenge 31 & 32
* Rewrite Racket solutions to be less imperative
  * Challenge 21

### Completed Tasks
* Convert Python solutions to Python3.
* Write proper documentation for all files
* Improve AES implementation
    * I made this implementation when I first started these challenges. At the time,
      I thought I was pretty good with Racket, but man oh man this implementation
      was embarrassing. I made lots of changes to the code, removing some really
      unnecessary code. I'm not sure what the performance increase is but I can
      imagine it is pretty good.
* Optimize slow Racket challenges
    * AES
      * Mostly just cleaner code with this one but there was a slight speed improvement.
    * Challenges 3-6
        * Saw MASSIVE speed improvement with this one. My original solutions were doing
        all sorts of bad things. The new solutions are much cleaner and faster.

## Challenges

### Set 1 - Basics :heavy_check_mark:

#### 1. Convert hex to base64 - :ballot_box_with_check:

I decided to go ahead and define all the encoding functions I'll need
throughout these exercises. The functions are used in pretty much every exercise
after this. Both languages had them in their libraries.

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
and the plaintext very quickly. 

#### 5. Implement Repeating-key XOR - :ballot_box_with_check:

#### 6. Break Repeating-key XOR - :ballot_box_with_check:

#### 7. AES in ECB Mode - :ballot_box_with_check:

<span style="color:green">Python (obviously) had a library function for AES-128.</span>

<span style="color:red">Racket did not have a library function so I implemented it
myself. I may go back and implement it in Python just for fun.</span>

#### 8. Detect AES in ECB Mode - :ballot_box_with_check:

### Set 2 - Block Crypto :heavy_check_mark:

#### 9. Implement PKCS#7 Padding - :ballot_box_with_check:

#### 10. Implement CBC Mode - :ballot_box_with_check:

#### 11. An ECB/CBC Detection Oracle - :ballot_box_with_check:

#### 12. Byte-at-a-time ECB Decryption (Simple) - :ballot_box_with_check:

The first really interesting challenge in the set.

The Racket solution is incredibly slow while the Python solution is almost
immediate. Not sure why.

#### 13. ECB Cut-and-paste - :ballot_box_with_check:

#### 14. Byte-at-a-time ECB Decryption (Harder) - :ballot_box_with_check:

<span style="color:green">The Python solution to this one is much cleaner and way, way faster. Not much
different from the first one other than needing to discover the size of the
secret prefix.</span>

#### 15. PKCS#7 Padding Validation - :ballot_box_with_check:

I did this one with challenge 9. I don't understand why they separated
the two functions when ```unpad``` is needed in previous exercises.

#### 16. CBC Bitflipping Attacks - :ballot_box_with_check:

### Set 3 - Block & Stream Crypto :x:

#### 17. The CBC Padding Oracle - :ballot_box_with_check:

This problem was a little difficult to grasp at first. My best resource for it
was http://www.exploresecurity.com/padding-oracle-decryption-attack/

#### 18. Implement CTR, The Stream Cipher Mode - :ballot_box_with_check:

#### 19. Break Fixed-Nonce CTR Mode Using Substitutions - :black_square_button:

Skipping this one until I feel like it because it will be hard to automate.

#### 20. Break Fixed-Nonce CTR Statistically - :black_square_button:

Skipping this one as well, even though it can be automated just because I should do 19 first.

#### 21. Implement the MT19937 Mersenne Twister RNG - :ballot_box_with_check:

This was fun to implement. I was shocked to see the execution time on this because the test generates 700 numbers, and finished in 9ms on my crappy laptop.

<span style="color:red">This is the first time I've used a class in Racket. I wanted to avoid using the class
but I didn't really see a way around it.</span>

#### 22. Crack an MT19937 Seed - :ballot_box_with_check:

#### 23. Clone an MT19937 RNG from Its Output - :ballot_box_with_check:

#### 24. Create the MT19937 Stream Cipher and Break It - :ballot_box_with_check:

### Set 4 - Stream Crypto and Randomness :heavy_check_mark:

#### 25. Break "Random Access Read/Write" AES CTR - :ballot_box_with_check:

#### 26. CTR Bitflipping - :ballot_box_with_check:

#### 27. Recover the Key from CBC with IV=Key - :ballot_box_with_check:

#### 28. Implement a SHA-1 Keyed MAC - :ballot_box_with_check:

I implemented SHA-1 myself because I'm an overachiever :smirk:

<span style="color:red">I was able to implement SHA-1 in Racket as a function, rather than
a class (unlike the Mersenne Twister),</span> <span style="color:green">but the Python solution was still
a class.</span>

#### 29. Break a SHA-1 Keyed MAC Using Length Extension - :ballot_box_with_check:

#### 30. Break an MD4 Keyed MAC Using Length Extension - :ballot_box_with_check:

This one took a while because I implemented MD4 myself as well (at this point,
why not?). The solution itself was almost identical to the previous one.

#### 31. Implement and Break HMAC-SHA1 with an Artificial Timing Leak - :ballot_box_with_check:

<span style="color:green">The Python solution works very well.</span>

<span style="color:red">
In Racket, I couldn't get it to work using
the web api because the messages would have random lag about every 5-10 requests.
I can't figure out why this happens or how to fix it, so for now, it uses simple
function calls to simulate web requests, which is admittedly a bad solution.
</span>

The solution does not work on a slower machine (like my old laptop), but it works
very well on my main pc (gaming). I guess this is to be expected. This solution
is also the only one (so far) that is not unit tested.

#### 32. Break HMAC-SHA1 with a Slightly Less Artificial Timing Leak - :ballot_box_with_check:

<span style="color:green">The Python solution worked for a delay as low as 15ms. </span>

<span style="color:red">The Racket solution only worked for a delay down to 30ms, which seems weird
considering that solution isn't using the web framework. </span>

The improved solutions are also very different.
Python made it all the way to 1ms (to my amazement), but the Racket solution
works for 20ms. I need to spend a lot more time on this one. Shelving for now...

### Set 5 - Diffie-Hellman and Friends :x:

#### 33. Implement Diffie-Hellman :ballot_box_with_check:

This was very simple and easy. Racket and Python both handle large numbers with
grace, but Racket really shines here. The solution is so elegant and fast. Python is no
less impressive. Both languages had modular exponentiation built in, so this challenge
took all of two minutes.

#### 34. Implement a MITM Key-Fixing Attack on Diffie-Hellman with Parameter Injection :ballot_box_with_check:

This seemed like it would be challenging at first and I was very tempted to Google the answer
to the Diffie-Hellman math, but (when you write it down) the answer is staring you in the face. The
exploit here is so incredibly simple.

<span style="color:green">
This is my first time using Python threads. It's a lot more like C threads
than I would have expected. I was also surprised to find that ```Queue```
was the best replacement for Racket's ```channel```.
</span>


#### 35. Implement DH with Negotiated Groups, and Break with Malicious 'g' Parameters :ballot_box_with_check:

This one was a little harder just because of g=p-1 has two possible
key values, but still pretty easy.

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

# Challenge 29
## Break a SHA-1 keyed MAC using length extension.

### Secret-prefix SHA-1 MACs are trivially breakable.
### The attack on secret-prefix SHA1 relies on the fact
### that you can take the output of SHA-1 and use it as
### a new starting for SHA-1, thus taking an arbitrary 
### SHA-1 hash and 'feeding it more data'.
### Since the key precedes the data in secret-prefix,
### any additional data you feed the sHA-1 hash in
### this fassion will appear to have been hashed with 
### the secret key.
### To carry out the attack, you'll need to account for the
### fact that SHA-1 is 'padded'

# Challenge 34
## Implement a MITM Key-Fixing Attack on Diffie-Hellman
## with Parameter Injection
import threading, os, random, sys, Queue
sys.path.insert(0, "../set2")
import c33, c10, c9

DEBUG = False
### Use the code you just worked out to build a protocol and an "echo"
### bot. You don't actually have to do the network part of this if you
### don't want; just simulate that. The protocol is:
###   A->B
###      Send p,g,A
###   B->A
###      Send B
###   A->B
###      Send AES-CBC(SHA1(s)[0:16],iv=random(16),msg)+iv
###   B->A
###      Send AES-CBC(SHA1(s)[0:16],iv=random(16),A's msg)+iv
def alice(to_bob, from_bob, msgs):
    """
    Simulates Alice's communication to Bob with DH. Alice checks that
    the echo she receives back is the same as the message she sent.

    Args:
        to_bob: a queue for sending messages out to bob
        from_bob: a queue for receiving messages from bob
        msgs: list of messages to send to bob
    """
    p   = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    p +=  "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    p +=  "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    p +=  "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    p +=  "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    p +=  "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    p +=  "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    p +=  "fffffffffffff"
    p = int(p, 16)
    g   = 2
    a,A = c33.diffie_hellman(p,g)
    # A->B Send p,g,A
    to_bob.put([p,g,A])
    # B->A Send B
    B           = from_bob.get()
    session_key = c33.make_session_key(B,a,p)
    key         = session_key[0:16]

    for msg in msgs:
        if DEBUG:
            print 'Sending msg: ' + str(msg)
        iv    = os.urandom(16)
        e_msg = iv + c10.aes_128_cbc_encrypt(c9.pkcs7_pad(msg), key, iv)
        # A->B Send AES-CBC(key,msg,iv) + iv
        to_bob.put(e_msg)
        # B->A echo
        echo     = from_bob.get()
        echo_msg = echo[16:]
        echo_iv  = echo[0:16]
        d_echo   = c10.aes_128_cbc_decrypt(echo_msg, key, echo_iv)
        d_echo   = c9.pkcs7_unpad(d_echo)
        if DEBUG:
            print 'Alice got echo: ' + str(d_echo)
        assert d_echo == msg, d_echo

def bob(to_alice, from_alice):
    """
    Simulates Bob's communication with Alice via DH. Bob decrypts the messages
    then sends them back after re-encrypting under a new IV.

    Args:
        to_alice: a queue for sending messages to alice
        from_alice: a queue for receiving messages from alice
    """
    # A->B Send p,g,A
    p,g,A       = from_alice.get()
    b,B         = c33.diffie_hellman(p,g)
    # B->A Send B
    to_alice.put(B)
    session_key = c33.make_session_key(A,b,p)
    key         = session_key[0:16]
    msg         = from_alice.get(0.5)

    while msg:
        msg_iv = msg[0:16]
        msg    = msg[16:]
        d_msg  = c10.aes_128_cbc_decrypt(msg,key,msg_iv)
        d_msg  = c9.pkcs7_unpad(d_msg)
        iv     = os.urandom(16)
        d_msg  = c9.pkcs7_pad(d_msg) # i know this weird but it does perform a check
        echo   = c10.aes_128_cbc_encrypt(d_msg,key,iv)
        echo   = iv + echo
        to_alice.put(echo)
        try:
            msg    = from_alice.get(timeout=0.5)
        except:
            msg = False

### (In other words, derive an AES key from DH with SHA1, use it
### in both directions, and do CBC with random IVs appended or prepended
### to the message).

### Now implement the following MITM attack:
###   A->M
###      Send p,g,A
###   M->B
###      Send p,g,p
###   B->M
###      Send B
###   M->A
###      Send p
###   A->M
###      Send AES-CBC(SHA1(s)[0:16],iv=random(16),msg)+iv
###   M->B
###      Relay to B
###   B->M
###      Send AES-CBC(SHA1(s)[0:16],iv=random(16),A's msg)+iv
###   M->A
###      Relay to A
def mallory(to_alice, from_alice, to_bob, from_bob):
    """
    Simulates the man-in-the-middle attack by sending bad values
    and decrypting the messages being passed.

    Args:
        to_alice: queue for sending messages to alice
        from_alice: queue for messages from alice
        to_bob: queue for sending messages to bob
        from_bob: queue for messages from bob
    """
    # A->M Send p,g,A
    p,g,A       = from_alice.get()
    # M->B Send p,g,p
    to_bob.put([p,g,p])
    # B->M Send B
    B           = from_bob.get()
    # M->A Send p
    to_alice.put(p)
    session_key = c33.make_session_key(p, 1, p)
    key         = session_key[0:16]
    # A->M Send AES-CBC(blah blah)
    msg         = from_alice.get()
    dec_msgs    = []
    while msg:
        # M->B Relay to B
        to_bob.put(msg)
        ## Decrypt the message
        d_msg = c10.aes_128_cbc_decrypt(msg[16:],key,msg[0:16])
        d_msg = c9.pkcs7_unpad(d_msg)
        dec_msgs.append(d_msg)
        to_alice.put(from_bob.get())
        try:
            msg = from_alice.get(timeout=0.5)
        except:
            msg = False
    return dec_msgs

### M should be able to decrypt the messages. "A" and "B" in the protocol
### --- the public keys, over the wire --- have been swapped out with "p".
### Do the DH math on this quickly to see what that does to the predicability
### of the key.

### Decrypt the messages from M's vantage point as they go by.

### Note that you don't actually have to inject bogus parameters to make
### this attack work; you could just generate Ma, MA, Mb, and MB as valid
### DH parameters to do a generic MITM attack. But do the paramater injection
### attack; it's going to come up again.
def main():
    msgs = [
    b"Say, you're good.",
    b"Thanks.",
    b"Ha! Darn.",
    b"Mary had a little lamb whose fleece was white as...PICKLED FISH LIPS!",
    b"eep!",
    b"Sea weavle.",
    b"Gorgy smorgy.",
    b"At least I'm safe inside my mind.",
    b"Gahhh!"]
    a_in     = Queue.Queue()
    b_in     = Queue.Queue()
    a_out    = Queue.Queue()
    b_out    = Queue.Queue()
    a_thread = threading.Thread(target=alice, args=(a_out,a_in,msgs))
    b_thread = threading.Thread(target=bob, args=(b_out,b_in))
    a_thread.start()
    b_thread.start()
    eve_msgs = mallory(a_in, a_out, b_in, b_out)
    a_thread.join(2)
    b_thread.join(2)
    assert msgs == eve_msgs, eve_msgs

if __name__ == "__main__" :
    main()
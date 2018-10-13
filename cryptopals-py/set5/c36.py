"""
**Challenge 36**

*Implement Secure Remote Password (SRP)*

To understand SRP, look at how you generate an AES key from DH; now just observe
you can do the "opposite" operation and generate a numeric parameter from a
hash. Then:

Replace A and B with C and S (client & server)::

    C & S
        Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    S
        1. Generate salt as random integer
        2. Generate string xH = SHA256(salt || password)
        3. Convert xH to integer x somehow (put 0x on hexdigest)
        4. Generate v = g**x % N
        5. Save everything but x, xH
    C->S
        Send I, A = g**a % N (a la Diffie-Hellman)
    S->C
        Send salt, B = k*v + g ** b % N
    S,C
        Compute string uH = SHA256(A || B), u = integer of uH
    C
        1. Generate string xH = SHA256(salt || password)
        2. Convert xH to integer x somehow (put 0x on hexdigest)
        3. Generate S = (B - k * g**x)**(a + u*x) % N
        4. Generate K = SHA256(S)
    S
        1. Generate S = (A * v**u)**b % N
        2. Generate K = SHA256(S)
    C->S
        Send HMAC-SHA256(K, salt)
    S->C
        Send 'OK' if HMAC-SHA256(k, salt) validates

You're going to want to do this at a REPL of some sort; it may take a couple of
tries.

It doesn't matter how you go from integer to string or string to integer (where
things are going in or out of SHA256) as long as you do it consistently. I
tested by using the ASCII decimal representation of integers as input to SHA256,
and by converting the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password into the
public keys. The server also takes an extra step to avoid storing an easily
crackable password-equivalent.
"""
import os, struct, sys, queue, unittest, threading
from hashlib import sha256
sys.path.insert(0, '../set1')
import c1, c2

DEBUG = False

def int_to_bytes(x):
    """
    Converts an integer to a bytestring. Stolen from StackOverflow.

    Args:
        x: The number to convert to bytes

    Returns:
        The bytestring representation of x
    """
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def hmac_sha256(key, message):
    """
    Creates an HMAC using SHA-256.

    Args:
        key: The HMAC key.
        message: The message to generate the MAC for.

    Returns:
        The HMAC for the message under the given key
    """
    # If the key is longer than the blocksize,
    # then truncate it by hashing it
    if (len(key) > 64):
        key = sha256(key).digest()

    # If the key is shorter than blocksize,
    # pad with 0s
    if (len(key) < 64):
        key = key + (b'\x00' * (64 - len(key)))

    o_pad = c2.xorstrs(key, b'\x5c'*64)
    i_pad = c2.xorstrs(key, b'\x36'*64)
    i_msg = i_pad + message
    o_msg = o_pad + sha256(i_msg).digest()
    return sha256(o_msg).digest()

class SRPServer():
    """
    Represents a server that uses Secure Remote Password to authenticate users.

    Attributes:
        N (int): A NIST prime
        I (bytestring): Email of user
        salt (bytestring): Random integer
        v (int): Value for the password
    """
    def __init__(self, prime, email, password):
        """
        Initializes the class with a provided NIST prime, email, and password.
        Computes salt, v so that the password does not need to be saved.

        Args:
            prime (int): The NIST prime used by both client and server
            email (bytestring): The email for the user
            password (bytestring): The password for the user
        """
        self.N    = prime
        self.g    = 2
        self.k    = 3
        self.I    = email
        self.salt = os.urandom(8)
        xH        = sha256(self.salt + password).digest()
        if DEBUG:
            print('SERVER: salt: ' + str(c1.asciitohex(self.salt)))
            print('SERVER: xH: ' + str(c1.asciitohex(xH)))
        x         = int.from_bytes(xH, byteorder='big')
        self.v    = pow(self.g, x, self.N)

    def authenticate(self, email, A, inp, out):
        """
        Authenticates the user.

        Args:
            email (bytestring): The user's email
            A (int): The SRP value for authentication
            inp (queue): Input queue for communication
            out (queue): Output queue for communication
        """
        threading.Thread(target=self.__auth, args=(email, A, inp, out)).start()

    def __auth(self, email, A, inp, output):
        # Send salt, B
        b           = int.from_bytes(os.urandom(8), byteorder='big')
        B           = self.k * self.v + pow(self.g, b, self.N)
        if DEBUG:
            print('SERVER: B: ' + str(B))
        output.put([self.salt, B])
        # Compute uH
        uH          = sha256(int_to_bytes(A) + int_to_bytes(B)).digest()
        if DEBUG:
            print('SERVER: uH: ' + str(c1.asciitohex(uH)))
        u           = int.from_bytes(uH, byteorder='big')
        # Generate S= (A * v**u)**b % N, K
        S           = pow(A * pow(self.v, u, self.N), b, self.N)
        K           = sha256(int_to_bytes(S)).digest()
        hmac        = hmac_sha256(self.salt, K)
        if DEBUG:
            print('SERVER: S: ' + str(S))
            print('SERVER: K: ' + str(c1.asciitohex(K)))
            print('SERVER: hmac: ' + str(c1.asciitohex(hmac)))
        client_hmac = inp.get()
        output.put(hmac == client_hmac)

class SRPClient():
    def __init__(self, prime, server):
        """
        Initializes the class with a provided NIST prime and a server to
        communicate with.

        Args:
            prime (int): The NIST prime used by both client and server
            server (SRPServer): The server to talk to
        """
        self.N      = prime
        self.g      = 2
        self.k      = 3
        self.server = server

    def login(self, email, password):
        """
        Attempts to log into the SRP server with the given credentials.

        Args:
            email: The email of the user
            password: The password of the user

        Returns:
            True if successful login
        """
        a       = int.from_bytes(os.urandom(8), byteorder='big')
        A       = pow(self.g, a, self.N)
        # Send I, A
        out     = queue.Queue()
        inp     = queue.Queue()
        self.server.authenticate(email, A, out, inp)
        # S->C salt, B
        salt, B = inp.get()
        if DEBUG:
            print('CLIENT: salt: ' + str(c1.asciitohex(salt)))
            print('CLIENT: B: ' + str(B))
        # Compute uH
        uH      = sha256(int_to_bytes(A) + int_to_bytes(B)).digest()
        u       = int.from_bytes(uH, byteorder='big')
        # Generate xH, K, S= (B - k * g**x)**(a + u*x) % N
        xH      = sha256(salt + password).digest()
        x       = int.from_bytes(xH, byteorder='big')
        S       = pow(B - self.k * pow(self.g, x, self.N), (a + u*x), self.N)
        K       = sha256(int_to_bytes(S)).digest()
        hmac    = hmac_sha256(salt, K)
        if DEBUG:
            print('CLIENT: uH: ' + str(c1.asciitohex(uH)))
            print('CLIENT: xH: ' + str(c1.asciitohex(xH)))
            print('CLIENT: S: ' + str(S))
            print('CLIENT: K: ' + str(c1.asciitohex(K)))
            print('CLIENT: HMAC: ' + str(c1.asciitohex(hmac)))
        out.put(hmac)
        auth = inp.get()
        return auth

class TestSRP(unittest.TestCase):
    def test_challenge_36(self):
        p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        p +=  "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        p +=  "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        p +=  "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        p +=  "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        p +=  "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        p +=  "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        p +=  "fffffffffffff"
        p = int(p, 16)
        email    = b'ssquarepants@krustyk.com'
        password = b'imready'
        server   = SRPServer(p, email, password)
        client   = SRPClient(p, server)
        self.assertTrue(client.login(email, password))
        self.assertFalse(client.login(email, b'imnotready'))

if __name__ == "__main__":
    unittest.main()
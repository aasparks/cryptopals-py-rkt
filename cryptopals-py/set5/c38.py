"""
**Challenge 38**

*Offline Dictionary Attack on Simplified SRP*::

    S
        x = SHA256(salt || password)
        v = g**x % N
    C->S
        I, A = g**a % N
    S->C
        salt, B = g**b % N, u = 128-bit random number
    C
        x = SHA256(salt || password)
        S = B**(a + ux) % N
        K = SHA256(S)
    S
        S = (A * v**u)**b % N
        K = SHA256(S)
    C->S
        Send HMAC-SHA256(K, salt)
    S->C
        Send 'OK' if HMAC-SHA256(K, salt) validates

Note that in this protocol, the server's "B" parameter doesn't depend on the
password (it's just a Diffie-Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker, pose as the server and use arbitrary
values for b,B,u, and salt.

Crack the password from A's HMAC-SHA256(K, salt)
"""
from c36 import int_to_bytes, hmac_sha256
from hashlib import sha256
import unittest, sys, queue, os, threading
sys.path.insert(0, '../set1')
import c1, c2

DEBUG = False

class SimplifiedSRPServer():
    """
    Represents a server that uses a simplified version of Secure Remote
    Password to authenticate users.

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
        x      = int.from_bytes(xH, byteorder='big')
        self.v = pow(self.g, x, self.N)

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
        b = int.from_bytes(os.urandom(8), byteorder='big')
        B = pow(self.g, b, self.N)
        if DEBUG:
            print('SERVER: B: ' + str(B))
        u = int.from_bytes(os.urandom(16), byteorder='big')
        output.put([self.salt, B, u])
        # Generate S = (A * v**u)**b % N, K
        S    = pow(A * pow(self.v, u, self.N), b, self.N)
        K    = sha256(int_to_bytes(S)).digest()
        hmac = hmac_sha256(self.salt, K)
        if DEBUG:
            print('SERVER: S: ' + str(S))
            print('SERVER: K: ' + str(c1.asciitohex(K)))
            print('SERVER: hmac: ' + str(c1.asciitohex(hmac)))
        client_hmac = inp.get()
        output.put(hmac == client_hmac)

class MITMSimplifiedSRPServer():
    def __init__(self, prime, email, password):
        """
        Initializes the class with a provided NIST prime, email, and password.
        Computes salt, v so that the password does not need to be saved.

        Args:
            prime (int): The NIST prime used by both client and server
            email (bytestring): The email for the user
            password (bytestring): The password for the user
        """
        # Setting the password list small for testing but really, you would
        # need to sit here and do a long dictionary attack. I'm not wasting
        # my time.
        self.password_list = [b'password', b'password1', b'imready', b'ready',
                         b'krustykrab', b'1234567890', b'invalid']
        self.N    = prime
        self.g    = 2
        self.k    = 3
        self.I    = email
        self.salt = os.urandom(8)
        xH        = sha256(self.salt + password).digest()
        if DEBUG:
            print('SERVER: salt: ' + str(c1.asciitohex(self.salt)))
            print('SERVER: xH: ' + str(c1.asciitohex(xH)))
        x      = int.from_bytes(xH, byteorder='big')
        self.v = pow(self.g, x, self.N)

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
        self.salt = b'0' * 8
        b = 1
        B = 2 # x needs to not be canceled out by bad math
        u = 1 # these two values make it S = g**(a+x) % N
        output.put([self.salt, B, u])
        # Generate S = (A * v**u)**b % N, K
        if DEBUG:
            print('SERVER: S: ' + str(S))
            print('SERVER: K: ' + str(c1.asciitohex(K)))
            print('SERVER: hmac: ' + str(c1.asciitohex(hmac)))
        client_hmac = inp.get()
        self.__dictionary_attack(client_hmac, self.salt, A, u)
        output.put(False)

    def __dictionary_attack(self, client_hmac, salt, A, u):
        for password in self.password_list:
            xH   = sha256(salt + password).digest()
            x    = int.from_bytes(xH, byteorder='big')
            v    = pow(self.g, x, self.N)
            S    = (A * v) % self.N
            K    = sha256(int_to_bytes(S)).digest()
            hmac = hmac_sha256(salt, K)
            if hmac == client_hmac:
                self.password = password
                return
        raise RuntimeError('Password not found')

class SimplifiedSRPClient():
    def __init__(self, prime, server):
        """
        Represents a simplified SRP Client.

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
        # S->C salt, B, u
        salt, B, u = inp.get()
        if DEBUG:
            print('CLIENT: salt: ' + str(c1.asciitohex(salt)))
            print('CLIENT: B: ' + str(B))
            print('CLIENT: u: ' + str(u))

        # Generate xH, K, S= (B - k * g**x)**(a + u*x) % N
        xH   = sha256(salt + password).digest()
        x    = int.from_bytes(xH, byteorder='big')
        S    = pow(B, (a+u*x), self.N)
        K    = sha256(int_to_bytes(S)).digest()
        hmac = hmac_sha256(salt, K)
        if DEBUG:
            print('CLIENT: xH: ' + str(c1.asciitohex(xH)))
            print('CLIENT: S: ' + str(S))
            print('CLIENT: K: ' + str(c1.asciitohex(K)))
            print('CLIENT: HMAC: ' + str(c1.asciitohex(hmac)))
        out.put(hmac)
        auth = inp.get()
        return auth

class TestSRP(unittest.TestCase):
    def test_simple_srp(self):
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
        server   = SimplifiedSRPServer(p, email, password)
        client   = SimplifiedSRPClient(p, server)
        self.assertTrue(client.login(email, password))
        self.assertFalse(client.login(email, b'imnotready'))

    def test_mitm_srp(self):
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
        b = 0
        B = 0
        u = 0
        salt = 0
        server = MITMSimplifiedSRPServer(p, email, password)
        client = SimplifiedSRPClient(p, server)
        self.assertFalse(client.login(email, password))
        self.assertTrue(server.password == password)

if __name__ == "__main__":
    unittest.main()
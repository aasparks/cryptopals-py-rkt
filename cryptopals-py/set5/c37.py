"""
**Challenge 37**

*Break SRP with a Zero Key*

Get your SRP working in an actual client-server setting. "Log in" with a valid
password using the protocol.

Now log in without your password by having the client send 0 as its "A" value.
What does this do to the "S" value that both sides compute?

Now log in without your password by having the client send N, N*2, &c.
"""
from c36 import SRPServer, int_to_bytes, hmac_sha256
from hashlib import sha256
import unittest, sys, queue
sys.path.insert(0, '../set1')
import c1, c2

DEBUG = False

class SRPClientA():
    def __init__(self, prime, server):
        """
        Initializes the class with a provided NIST prime and a server to
        communicate with. Accepts a malicious value for A to send to the
        server.

        Args:
            prime (int): The NIST prime used by both client and server
            server (SRPServer): The server to talk to
        """
        self.N      = prime
        self.g      = 2
        self.k      = 3
        self.server = server

    def login(self, email, password, A):
        """
        Attempts to log into the SRP server with the given credentials.

        Args:
            email: The email of the user
            password: The password of the user
            A: A malicious A value. Must be 0, or multiple of N

        Returns:
            True if successful login
        """
        # Send I, A
        out     = queue.Queue()
        inp     = queue.Queue()
        self.server.authenticate(email, A, out, inp)
        # S->C salt, B
        salt, B = inp.get()
        if DEBUG:
            print('CLIENT: salt: ' + str(c1.asciitohex(salt)))
            print('CLIENT: B: ' + str(B))
        if A % self.N != 0:
            raise ValueError('Not a valid malicious A value')
        K       = sha256(int_to_bytes(0)).digest()
        hmac    = hmac_sha256(salt, K)
        if DEBUG:
            print('CLIENT: K: ' + str(c1.asciitohex(K)))
            print('CLIENT: HMAC: ' + str(c1.asciitohex(hmac)))
        out.put(hmac)
        auth = inp.get()
        return auth

class TestSRP(unittest.TestCase):
    def setUp(self):
        p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        p +=  "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        p +=  "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        p +=  "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        p +=  "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        p +=  "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        p +=  "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        p +=  "fffffffffffff"
        p = int(p, 16)
        self.p = p
    def __run_test(self, A):
        email    = b'ssquarepants@krustyk.com'
        password = b'imready'
        server   = SRPServer(self.p, email, password)
        client   = SRPClientA(self.p, server)
        self.assertTrue(client.login(email, password, A))
        self.assertTrue(client.login(email, b'imnotready', A))

    def test_zero_key(self):
        self.__run_test(0)

    def test_n_key(self):
        self.__run_test(self.p)
        self.__run_test(self.p * 2)
        self.__run_test(self.p ** 2)

if __name__ == "__main__":
    unittest.main()
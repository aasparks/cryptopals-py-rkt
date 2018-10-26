#lang scribble/doc

@(require scribble/manual
          "../set5/c36.rkt")
@(require (for-label racket/class))

@title{Set 5}

This is the first set of number-theoretic cryptography challenges,
and also our coverage of message authentication.

This set is significantly harder than the last set. The concepts
are new, the attacks bear no resemblance to those of the previous
sets, and... math.

On the other hand, our favorite cryptanalytic attack ever
is in this set (you'll see it soon). We're happy with this
set. Don't wimp out here. You're almost done!

@section{Challenge 33}

@defmodule["set5/c33.rkt"]{
   @codeblock{
   For one of the most important algorithms in cryptography
   this exercise couldn't be a whole lot easier.

   Set a variable "p" to 37 and "g" to 5. This algorithm is so
   easy, I'm not even going to explain it. Just do what I do.

   Generate "a", a random number mod 37. Now generate "A", which is
   "g" raised to the "a" power mod 37
       A = (g ** a) % p

   Do the same for "b" and "B"

   "A" and "B" are public keys. Generate a session key with them;
   set "s" to "B" raised to the "a" power mod 37
      s = (B ** a) % p

   Do the same with A**b, check that you come up with the same "s"

   To turn "s" into a key, you can just hash it to create 128 bits
   of key material

   Ok, that was fun, now repeat the exercise with bignums like
   in the real world. Here are parameters NIST likes:
     p:
       ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
       e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
       3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
       6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
       24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
       c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
       bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
       fffffffffffff
    g: 2

   This is very easy to do in Python or Ruby or other high-level
   languages that auto-promote fixnums to bignums, but it isn't
   "hard" anywhere.

   Note that you'll need to write your own modexp, because you'll
   blow out your bignum library raising "a" to the 1024-bit-numberth
   power. You can find modexp routines on Rosetta Code for most
   languages.
   }

  @defproc[(diffie-hellman [p integer?] [g integer?]) (values integer? integer?)]{
  Computes the Diffie-Hellman private, public (in that order) key pair from
  the provided values for @racket[p] and @racket[g].
 }

  @defproc[(make-session-key [pub integer?] [priv integer?] [p integer?]) bytes?]{
  Creates a session key from the public, private key pair from Diffie-Hellman.
  (Note: the key pairs are B,a and A,b).
 }
}

@section{Challenge 34}

@defmodule["set5/c34.rkt"]{
   @codeblock{
   Use the code you just worked out to build a
   protocol and an "echo" bot. You don't actually
   have to do the network part of this if you don't
   want; just simulate that. The protocol is:
     A->B
       Send "p", "g", "A"
     B->A
       Send "B"
     A->B
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     B->A
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
   (In other words, derive an AES key from DH with SHA1, use it
   in both directions, and do CBC with random IVs appended or
   prepended to the message.)

   Now implement the following MITM attack:
     A->M
       Send "p", "g", "A"
     M->B
       Send "p", "g", "p"
     B->M
       Send "B"
     M->A
       Send "p"
     A->M
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     M->B
       Relay that to B
     B->M
       Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
     M->A
       Relay that to A

   M should be able to decrypt the messages. "A" and "B"
   in the protocol ---the public keys, over the wire ---
   have been swapped out with "p" Do the DH math on this
   quickly to see what that does to the predictability of
   the key.

   Decrypt the messages from M's vantage point as they go
   by.

   Note that you don't actually have to inject bogus paramaters
   to make this attack work; you could just generate Ma, MA,
   Mb, and MB as valid DH parameters to do a generic MITM attack.
   But do the parameter injection attack; it's going to come
   up again.
   }
  Nothing provided. Solves the problem.
}

@section{Challenge 35}

@defmodule["set5/c35.rkt"]{
   @codeblock{
   A->B
     Send "p", "g"
   B->A
     Send ACK
   A->B
     Send "A"
   B->A
     Send "B"
   A->B
     Send AES-CBC(SHA1(s)[0:16],iv=random(16),msg)+iv
   B->A
     Send AES-CBC(SHA1(s)[0:16],iv=random(16), A's msg)+iv

   Do the MITM attack again, but play with "g"
   What happens with:
     g = 1
     g = p
     g = p - 1

   Write atacks for each.
   }
   Nothing provided. Solves the problem.
}

@section{Challenge 36}

@defmodule["set5/c36.rkt"]
   @codeblock{
   To understand SRP, look at how you generate an AES
   key from DH; now, just observe you can do the
   "opposite" operation and generate a numeric
   parameter from a hash. Then:
   Replace A and B with C and S (client and server)

   C&S
     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

   S
     1. Generate salt as a random integer
     2. Generate string xH=SHA256(salt || password)
     3. Convert xH to integer x somehow (put 0x on hexdigest)
     4. Generate v= g**x % N
     5. Save everything but x, xH

  C->S
    Send I, A=g**a % N (a la Diffie-Hellman)
  S->C
    Send salt, B = kv + g**b % N
  S,C
    Compute string uH = SHA256(A || B), u = integer of uH
  C
    1. Generate string xH = SHA256(salt || password)
    2. Convert xH to integer x somehow
    3. Generate S = (B-k * g**x)**(a + u*x) % N
    4. Generate K = SHA256(S)
  S
    1. Generate S = (A * v**u)**b % N
    2. Generate K = SHA256(S)
  C->S
    Send HMAC-SHA256(K, salt)
  S->C
    Send "OK" if HMAC-SHA256(K, salt) validates

   You're going to want to do this at a REPL of some sort;
   it may take a couple of tries.

   It doesn't matter how you go from integer to string or string
   to integer (where things are going in or out of SHA256) as long
   as you do it consistently. I tested by using the ASCII decimal
   representation of integers as input to SHA256, and by converting
   the hexdigest to an integer when processing its output.

   This is basically Diffie-Hellman with a tweak of mixing the password
   into the public keys. The server also takes an extra step to avoid
   storing an easily crackable password-equivalent.
   }
 @defclass[SRPServer% object% ()]{

  Represents an instance of a Server using SRP.

  @defconstructor[([prime integer?]
                   [email bytes?]
                   [password bytes?])]{

   Creates an instance of an SRP Server that uses the given
   @racket[prime].

   The server must initialized with an @racket[email] and
   @racket[password] for login. It only accepts one valid login,
   because I'm too lazy to implement more.
  }

  @defmethod[(authenticate [email bytes?] [A integer?] [in channel?] [out channel?]) void]{
   Authenticates via SRP the given @racket[email] and @racket[A], SRP public
   key from the @racket[SRPClient%].

   Communicates with the client via the given @racket[in] and @racket[out]
   channels. Sends @racket[true] to the @racket[out] channel if the
   credentials authenticate.
 }}

 @defclass[SRPClient% object% ()]{

  Represents an instance of a client using SRP.

  @defconstructor[([prime integer?]
                   [server (is-a SRPServer%)])]{

   Creates an instance of an SRP Client that uses the given
   @racket[prime].

   The @racket[server] to communicate with must be given at
   initialization time.
  }

  @defmethod[(login [email bytes?] [password bytes?]) boolean?]{
   Attempts to log in to the @racket[SRPSever%] with the given
   credentials. Returns true on success.
 }}

#lang scribble/doc

@(require scribble/manual)

@title{Set 4}

This is the last set of block cipher cryptography
challenges, and also our coverage of message
authentication.

This set is much easier than the last set. We
introduce some new concepts, but the attacks
themselves involve less code than, say, the
CBC padding oracle.

Things get significantly trickier in the next
two sets. A lot of people drop off after set 4.

@section{Challenge 25}

@defmodule["set4/c25.rkt"]{
   @codeblock{
   Back to CTR. Encrypt the recovered plaintext from this
   file (the ECB exercise) under CTR with a random key
   (for this exercise the key should be unknown to you,
   but hold on to it)

   Now, write the code that allows you to "seek" into
   the ciphertext, decrypt, and re-encrypt with different
   plaintext. Expose this as a function, like,
   "edit(ciphertext, key, offset, newtext)"

   Imagine the "edit" function was exposed to attackers
   by means of an API call that didn't reveal the key
   or the original plaintext; the attacker has the
   ciphertext and controls the offset and "new text"

   Recover the original plaintext.
   }

  @defproc[(api-edit [ct bytes?] [offset integer?] [new-text bytes?]) bytes?]{
  Edits the AES-128-CTR encrypted @racket[ct] by changing the text
  at @racket[offset] to @racket[new-text].
 }

  @defproc[(recover-plaintext) bytes?]{
  Uses api-edit to recover the plaintext using only the ciphertext.
 }
}

@section{Challenge 26}

@defmodule["set4/c26.rkt"]{
   @codeblock{
   There are people in the world that believe that CTR resists bit
   flipping attacks of the kind to which CBC mode is susceptible.

   Re-implement the CBC bitflipping exercise from earlier to use CTR
   mode instead of CBC mode. Inject an "admin=true" token.
   }

  Nothing provided. Just solves the problem.
}

@section{Challenge 27}

@defmodule["set4/c27.rkt"]{
   @codeblock{
   Take your code from exercise 16 and modify it so that it repurposes the key
   for CBC encryption as the IV.

   Applications sometimes use the key as an IV on the auspices that both the sender and the
   receiver have to know the key already, and can save some space by using it as both a
   key and an IV.

   Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get
   the receiver to decrypt a value that will reveal the key.

   The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for
   ASCII compliance. Noncomplaint messages should raise an exception or return an error that
   includes the decrypted plaintext (this happens all the time in real systems, for what it's
   worth)

   Use your code to encrypt a message that is 3 blocks long:
      AES-CBC(P1, P2, P3) -> C1, C2, C3

   Modify the message (you are now the attacker):
      C1, C2, C3 -> C1, C0, C1

   Decrypt the message (you are now the receiver) and raise the
   appropriate error if high-ASCII is found.

   As the attacker, recovering the plaintext from the, extract the key:
      P'1 XOR P'3
   }

  @defproc[(verify-url [url bytes?]) bytes?]{
  Verifies that a URL is ASCII-compliant. If not, it @racket[raise]s an
  error that contains the non-complaint URL.
 }
  @defproc[(extract-key) bytes?]{
  Extracts the key from the encryption oracle that is using the key as the IV.
 }
}

@section{Challenge 28}

@defmodule["set4/c28.rkt"]{
   @codeblock{
   Find a SHA-1 implementation in the language
   you code in.

   Write a function to authenticate a message
   under a secret key by using a secret-prefix
   MAC, which is simply:
      SHA1(key || message)

   Verify you cannot tamper with the message without breaking
   the MAC you've produced, and that you can't produce a new
   MAC without knowing the key.
   }

  @defproc[(sha1-mac [msg bytes?]) bytes?]{
  Produces the SHA-1 keyed MAC for the given @racket[msg].
 }
}

@section{Challenge 29}

@defmodule["set4/c29.rkt"]{
   @codeblock{
   Secret-prefix SHA-1 MACs are trivially breakable.

   The attack on secret-prefix SHA-1 relies on the fact that you
   can take the output of SHA-1 and use it as a new starting point
   for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it
   more data"

   Since the key precedes the data in secret-prefix, any additional
   data you feed the SHA-1 hash in this fashion will appear to have
   been hashed with the secret key.

   To carry out the attack, you'll need to account for the fact that
   SHA-1 is "padded" with the bit-length of the message; your
   forged message will need to include that padding. We call this
   glue padding. The final message you actually forge will be:
     SHA1(key || original-message || glue-padding || new-message)

   (where the final padding on the whole constructed message is
   implied)

   Note that to generate the glue padding, you'll need to know the
   original bit length of the message; the message itself is known
   to the attacker, but the secret key isn't, so you'll need to guess
   at it.

   This sounds more complicated than it is in practice.

   To implement the attack, first write the function that computes
   the MD padding of an arbitrary message and verify that you're
   generating the same padding that your SHA-1 implementation is using.
   This should take you 5-10 minutes.

   Now take the SHA-1 secret-prefix MAC of the message you want to
   forge --- this is just a SHA-1 hash --- and break it into 32-bit
   SHA-1 registers.

   Modify your SHA-1 implementation so that callers can pass in new
   values for the registers (they normally start at magic numbers)
   Whith the registers 'fixated', hash the additional data you want
   to forge.

   Using this attack, generate a secret-prefix MAC under a secret
   key (choose a random word) of the string
    "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

   Forge a variant of this message that ends with ";admin=true"
   }

  Nothing provided. Solves the problem.
}

@section{Challenge 30}

@defmodule["set4/c30.rkt"]{
   @codeblock{
   Second verse, same as the first, but use MD4
   instead of SHA-1. Having done this attack once
   against SHA-1, the MD4 variant should take much
   less time; mostly just the time you'll spend
   Googling for an implementation of MD4.
  }

  Nothing provided. Solves the problem.
}
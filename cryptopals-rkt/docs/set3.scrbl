#lang scribble/doc

@(require scribble/manual)

@title{Set 3}

This is the next set of block cipher cryptography challenges
(even the randomness stuff here plays into block cipher crypto).

This set is moderately difficult. It includes a famous attack
against CBC mode, and a "cloning" attack on a popular RNG that
can be annoying to get right.

We've also reached a point in the crypto challenges where
all the challenges, with one possible exception, are valuable
in breaking real-world crypto.

@section{Challenge 17}

@defmodule["set3/c17.rkt"]{
   @codeblock{
   This is the best-known attack on modern block-cipher cryptography.

   Combine your padding code and your CBC code
   to write two functions.

   The first function should select at random one
   of the following strings, generate a random AES
   key (and save it), pad the string, and CBC
   encrypt it under that key.

   The second function should consume the ciphertext produced by
   the first function, decrypt it, check its padding, and return
   true or false depending on whether the padding is valid.

   It turns out it's possible to decrypt the ciphertexts provided
   by the first function.

   The decryption here depends on a side-channel leak by the
   decryption function. The leak is the error message that the
   padding is valid or not.

   You can find 100 web pages on how this attack works, so I won't
   re-exlain it. What I'll say is this:

   The fundamental insight behind this attack is that the byte
   01h is valid padding, and occur in 1/256 trails of "randomized"
   plaintexts produced by decrypting a tampered ciphertext.

   02h is isolation is not valid padding.
   02h02h is valid padding, but is much less likely to occur randomly.
   03h03h03h is even less likely.

   So you can assume that if you corrupt a decryption AND it had valid
   padding, you know what the padding byte is.

   It is easy to get tripped up on the fact that CBC plaintexts are
   padded. Padding oracles have nothing to do with the actual
   padding on a CBC plaintext. It's an attack that targets a specific
   bit of code that handles decryption. You can mount a padding oracle
   on any CBC block, whether it's padded or not.
   }
}

@section{Challenge 18}

@defmodule["set2/c18.rkt"]{
@codeblock{
   The string:
      "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

   ...decrypts to something approximating English in CTR mode, which is an
   AES block cipher mode that turns AES into a stream cipher, with the
   following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)

   CTR mode is very simple.

   Instead of encrypting the plaintext, CTR mode encrypts a
   running counter, producing a 16 byte block of keystream,
   which is XOR'd against the plaintext.

   For instance, for the first 16 bytes of a message with
   these parameters:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
   ...for the next 16 bytes:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
   ...and then:

      keystream = AES("YELLOW SUBMARINE",
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

   CTR mode does not require padding; when you run out of plaintext,
   you just stop XOR'ing keystream and stop generating keystream.

   Decryption is identical to encryption. Generate the same keystream,
   XOR, and recover the plaintext.

   Decrypt the string at the top of this function, then use your
   CTR function to encrypt and decrypt other things.
}
 This is provided by @racket["util/aes.rkt"]
 }

@section{Challenge 19}

@defmodule["set3/c19.rkt"]{
   @codeblock{
   Take your CTR encrypt/decrypt function and fix its nonce value to 0.
   Generate a random AES key.

   In successive encryptions, encrypt each line of the base64 decodes of the following,
   producing multiple independent ciphertexts.

   Because the CTR nonce wasn't randomized for each encryption, each ciphertext
   has been encrypted against the same keystream. This is very bad.

   Understanding that, like most stream ciphers, the actual encryption of a byte
   of data boils down to a single XOR operation, it should be plain that:
       CT-BYTE ^ PT-BYTE = KEYSTREAM-BYTE
   And since the keystream is the same for every ciphertext:
       CT-BYTE ^ KEYSTREAM-BYTE = PT-BYTE

   Attack this cryptosystem piecemeal: guess letters, use expected English language
   frequence to validate guesses, catch common trigrams, and so on.
}
    TBD
    }

@section{Challenge 20}

@defmodule["set3/c20.rkt"]{
   @codeblock{
   In this file find a similar set of Base64'd plaintext.
   Do with them exactly what you did with the first, but
   solve the problem differently.

   Instead of making spot guesses at to known plaintext,
   treat the collection of ciphertexts the same way you would
   repeating-key XOR.

   Obviously, CTR encryption appears different from repeated-key
   XOR, but with a fixed nonce they are effectively the same thing.

   To exploit this: take your collection of ciphertexts and
   truncate them to a common length (the length of the smallest
   ciphertext will work)

   Solve the resulting concatenation of ciphertexts as if for
   repeating-key XOR, with a key size of the length of the
   ciphertext you XOR'd.
 }
    TBD
    }

@section{Challenge 21}

@defmodule["set3/c21.rkt"]{
   @codeblock{
   You can get the psuedocode for this from Wikipedia.

   If you're writing in Python, Ruby, or (gah) PHP,
   your language is probably already giving you MT19937
   as "rand()"; don't use rand. Write the RNG yourself.
 }
    This is provided by @racket["util/mt19937.rkt"].
    }

@section{Challenge 22}

@defmodule["set3/c22.rkt"]{
   @codeblock{
   Make sure your MT19937 accepts an integer seed value. Test it.

   Write a routine that performs the following operation:
    - Wait a random number of seconds betweeen 40 and 1000.
    - Seed the RNG with the current Unix timestamp
    - Wait a random number of seconds again.
    - Returns the first 32 bit output of the RNG.

   You get the idea. Go get coffee while it runs. Or
   just simulate the passage of time, although you're
   missing some of the fun of this exercise if you do that.

   From the 32 bit RNG output, discover the seed.
 }
  @defproc[(get-coffee [test boolean? #false]) (is-a MT19937%)]{
   Waits a random amount of time (or simulates the
   passage of time when @racket[test] is @racket[true]),
   then returns a new instance of MT19937% seeded with
   the time.
 }
  @defproc[(find-seed [num integer?]) integer?]{
   Looks for the seed that produced the given @racket[num]
   and returns it.
 }
    }

@section{Challenge 23}

@defmodule["set3/c23.rkt"]{
   @codeblock{
   The internal state of MT19937 consists of 624 32 bit integers.

   For each batch of 624 outputs, MT permutes that internal state.
   By permuting state regularly, MT19937 achievs a period of
   2^19937, which is Big.

   Each time MT19937 is tapped, an element of its internal state
   is subjected to a tempering function that diffuses bits through
   the result.

   The tempering function is invertible; you can write an untemper
   function that takes an MT19937 output and transforms it back into
   the corresponding element of the MT19937 state array.

   To invert the temper transform, apply the inverse of each of the
   operations in the temper transform in reverse order. There are two kinds
   of operations in the temper transform each applied twice; one is an XOR
   against a right-shifted value, and the other is an XOR against a left-shifted
   value AND'd with a magic number. So you'll need code to invert the "right"
   and the "left" operation.

   Once you have untemper working, create a new MT19937 generator, tap it for
   624 outputs, untemper each of them to recreate the state of the generator,
   and splice that state into a new instance of the MT19937 generator.

   The new spliced generator should predict the values of the original.
 }
  @defproc[(clone-mt19937 [mt (is-a MT19937%)]) (is-a MT19937%)]{
   Clones the @racket[mt] PRNG from it's output and returns a new one.
 }
    }

@section{Challenge 24}

@defmodule["set3/c24.rkt"]{
   @codeblock{
   You can create a trivial stream cipher out of any PRNG; use it to
    generate a sequence of 8 bit outputs and call those outputs a keystream.
    XOR each byte of plaintext with each successive byte of keystream.

    Write the function that does this for MT19937 using a 16-bit seed.
    Verify that you can encrypt and decrypt properly. This code should  look
    similar to your CTR code.

   Use your function to encrypt a known plaintext prefixed by a random
   number of random characters.

   From the ciphertext, recover the 'key' (seed)

   Use the same idea to generate a random 'password reset token' using
   MT19937 seeded from the current time.

   Write a function to check if any given password token is actually
   the product of an MT19937 PRNG seeded with the current time.
 }
  @defproc[(encryption-oracle [ptxt bytes?]) bytes?]{
   Encrypts the given plaintext under a secret key after prepending a
   random count of random bytes. 
 }

  @defproc[(get-seed) integer?]{
   Finds the seed that @racket[encryption-oracle] is using.
 }

  @defproc[(reset-token) bytes?]{
   Generates a reset token using MT19937 seeded from the current time. 
 }

  @defproc[(check-token [token bytes?]) bytes?]{
   Verifies the reset token is valid.
 }
    }
#lang scribble/doc

@(require scribble/manual)

@title{Set 2}

This is the first of several sets on block cipher
cryptography. This is bread-and-butter crypto, the
kind you'll see implemented in most web software
that does crypto.

This set is relatively easy. People that clear
set 1 tend to clear set 2 somewhat quickly.

Three of the challenges in this set are extremely
valuable in breaking real-world crypto; one allows
you to decrypt messages encrypted in the default
mode of AES, and the other two allow you to
rewrite messages encrypted in the most popular
modes of AES.

@section{Challenge 9}

@defmodule["set2/c9.rkt"]{
   @codeblock{
   A block cipher transforms a fixed-sized block of plaintext into
   ciphertext. But we almost never want to transform a single block;
   we encrypt irregularly sized messages.

   One way we account for irregularly-sized messages is by padding,
   creating a plaintext that is an even multiple of the blocksize.
   The most popular padding scheme is called PKCS#7.

   So: pad any block to a specific block length, by appending the number
   of bytes of padding to the end of the block. For instance,
     "YELLOW SUBMARINE"
   ...padded to 20 bytes would be
     "YELLOW SUBMARINE#x04#x04#x04#x04"
 }
   
   @defproc[(pkcs7-pad [bstr bytes?] [len integer? 16]) bytes?]{
   Pads out the given byte string using PKCS#7 standard.
   }
   @defproc[(pkcs7-unpad [bstr bytes?] [len integer? 16]) bytes?]{
   Unpads the given byte string that was padded with PKCS#7 and
   performs validation.
   }
}

@section{Challenge 10}

@defmodule["set2/c10.rkt"]{
   @codeblock{
   CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
   messages, desipite the fact that a block cipher natively only transforms
   individual blocks.
   
   In CBC mode, each ciphertext block is added to the next plaintext block
   before the next call to the cipher core.
   
   The first plaintext block, which has no associated previous ciphertext block,
   is added to a "fake 0th ciphertext block" called the initialization vector,
   or IV.
   
   Implement CBC mode by hand by taking the ECB function you wrote earlier, making
   it encrypt instead of decrypt, and using your XOR function from the previous
   exercise to combine them.
   
   The file here is intelligible when CBC decrypted against "YELLOW SUBMARINE"
   with an IV of all ASCII 0.
 }
   CBC mode is provided by the @racket["util/aes.rkt"] module above.
}

@section{Challenge 11}

@defmodule["set2/c11.rkt"]{
   @codeblock{
   Now that you have ECB and CBC working:
   
   Write a function to generate a random AES key that's just
   16 random bytes.
   
   Write a function that encrypts data under an unknown key ---
   that is, a function that generates a random key and encrypts
   under it.
   
   The function should look like
     (encryption-oracle your-input) => [MEANINGLESS JIBBER JABBER]
     
   Under the hood, have the function append 5-10 bytes before the
   plaintext and 5-10 bytes after the plaintext.
   
   Now have the function choose to encrypt under ECB 1/2 the time,
   and under CBC the other half. Just use random IV's each time
   for CBC. Use (rand 2) to decide which to use.
   
   Detect the block cipher mode the function is using each time. You
   should end up with a piece of code that, pointed at a black box
   that might be encrypting ECB or CBC, tells which one is happening.
 }
   @defproc[(ecb-or-cbc [ctxt bytes?]) boolean?]{
   Returns @racket[true] if the given @racket[ctxt] was encrypted
   in ECB mode, and @racket[false] if CBC mode.
   }
}

@section{Challenge 12}

@defmodule["set2/c12.rkt"]{
   @codeblock{
   Copy your oracle function to a new function that encrypts buffers under
   ECB mode using a consistent but unknown key.

   Now take that same function and have it append to the plaintext,
   BEFORE ENCRYPTING, the following string:
     Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
     YnkK

   Base64 decode the string before appending it.
   What you have now is a function that produces:
     (AES-128-ECB your-string||unknown-string random-key)

   It turns out: you can decrypt "unknown-string" with repeated calls
   to the oracle function!
   Here's roughly how:
     1. Feed identical bytes of your-string to the function 1 at a time
        to discover the block size.
     2. Detect that the function is using ECB. You know this, but do it anyway.
     3. Knowing the block size, craft an input block that is exactly 1 byte
        short. Think about what the oracle function is going to put in the
        last byte position.
     4. Make a dictionary of every possible last byte by feeding different
        strings to the oracle; for instance "AA", "AB", "AC", remember
        the first block of each invocation.
     5. Match the output of the one-byte-short input to one of the entries in your dictionary.
        You've now discovered the first byte of unknown-string.
     6. Repeat for the next byte
 }

    No functions have been provided by this module. It just solves the problem.
}

@section{Challenge 13}

@defmodule["set2/c13.rkt"]{
   @codeblock{
   Write a k=v parsing routine, as if for a structured
   cookie. The routine should take:
      foo=bar&baz=qux&zap=zazzle
   and produce:
        foo: "bar",
        baz: "qux",
        zap: "zazzle"

   Now write a function that encodes a user profile
   in that format, given an email address. You should
   have something like:
     (profile-for "foo@"@"barcom")
     
   ...and it should produce
        email: "foo@"@"barcom",
        uid: 10,
        role: "user"

   You function should NOT alow encoding "&" or "="

   Now two more easy functions. Generate a random AES key, then:
     1. Encrypt the encoded user profile under the key
     2. Decrypt the encoded user profile and parse it

   Using only the user input to (profile-for)
   (as an oracle to generate "valid" ciphertexts)
   and the ciphertexts themselves, make a role=admin
   profile.
 }

  @defproc[(encrypt-profile [email string?]) string?]{
   Creates a @racket[profile-for] the given @racket[email] and
   then encrypts the encoded profile information using AES-128-ECB.
   }

  @defproc[(decrypt-profile [ctxt bytes?]) hash?]{
   Decrypts the encrypted profile and parses into a hash, as described
   in the problem above.
   }

  @defproc[(create-admin-profile) hash?]{
   Performs the attack. Creates a valid admin profile and returns
   the hash result from @racket[decrypt-profile], containing a key, value
   pair ("admin", #true).
   }
}

  @section{Challenge 14}

@defmodule["set2/c14.rkt"]{
   @codeblock{
  Take your oracle from challenge 12. Now generate
  a random count of random bytes and prepend this string
  to every plaintext. You are now doing:
     (AES-128-ECB random-prefix||attacker-controlled||target-bytes random-key)

  Same goal: decrypt the target-bytes
 }

    No functions have been provided by this module. It just solves the problem.
}

  @section{Challenge 15}

@defmodule["set2/c15.rkt"]{
   @codeblock{
   Write a function that takes a plaintext, determines if it has valid
   PKCS#7 padding, and strips the padding off.

   The string:
      "ICE ICE BABY\x04\x04\x04\x04"
   ...has valid padding, and produces the result "ICE ICE BABY"

   The string:
      "ICE ICE BABY\x05\x05\x05\x05"
   ...does not have valid padding, nor does:
      "ICE ICE BABY\x01\x02\x03\x04"
      
   If you are writing in a language with exceptions, like Python or
   Ruby, make your function throw an exception on bad padding.

   Crypto nerds know where we're going with this. Bear with us.

 }
   Unpad is provided by the @racket["util/pkcs7.rkt"] module.
}

  @section{Challenge 16}

@defmodule["set2/c16.rkt"]{
   @codeblock{
   Generate a random AES key.
   Combine your padding code and CBC code to write two function.

   The first function should take an arbitrary input string,
   prepend the string
     "comment1=cooking%20MCs;userdata="
   ...and append the string
     ";comment2=%20like%20a%20pound%20of%20bacon"
   The function should quote out the ';' and '=' characters.
   The function should then pad out the input to the 16-byte
   AES block length and encrypt it under the random AES key.

   The second function should decrypt the string and look
   for the characters ";admin=true;"
   Return true or false based on whether the string exists.

   If you've written the first function properly, it should
   not be possible to provide user input to it that will
   generate the string the second function is looking for.
   We'll have to break the crypto to do that.

   Instead, modify the ciphertext (without knowledge of
   the AES key) to accomplish this.

   You're relying on the fact that in CBC mode,
   a 1-bit error in a ciphertext block:
      - Completely scrambles the block the error occurs in
      - Produces the identical 1-bit error(/edit) in the next ciphertext block.


 }
   Nothing is provided. Just solves the problem.
}
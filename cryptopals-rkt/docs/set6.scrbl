#lang scribble/doc

@(require scribble/manual)
@(require (for-label racket/class
                     "../set6/c41.rkt"))

@title{Set 5}

This is the last of our original crypto challenges.

This set exclusively covers number-theoretic cryptography,
and, in particular, RSA and DSA.

This set is hard. The concepts are again new. The attacks involve
some math --- but nothing you didn't learn in 9th grade --- and a
significant amount of programming.

But they're worth it. Two of these attacks in particular
are among the most valuable in real-world cryptography.

@section{Challenge 41}

@defmodule["set6/c41.rkt"]
 @codeblock{
   Nate Lawson says we should stop calling it "RSA padding"
   and start calling it "RSA armoring"; here's why.

   Imagine a web application, again with the Javascript
   encryption, taking RSA-encrypted messages which
   (again: Javascript) aren't padded before encryption
   at all.

   You can submit an arbitrary RSA blob and the server
   will return plaintext. But you can't submit the same
   message twice: let's say the server keeps hashes
   of previous messages for some liveness interval, and
   that the message has an embedded timestamp:
      time: 13563042762,
      social: '555-55-5555'

   You'd like to capture other people's messages and
   use the server to decrypt them. But when you try,
   the server takes the hash of the ciphertext and
   uses it to reject the request. Any bit you flip in
   the ciphertext irrevocably scrambles the decryption.

   This turns out to be trivially breakable:
      * Capture the ciphertext C
      * Let N and E be the public modulus and exponent
        respectively
      * Let S be a random number > 1 mod N. Doesn't matter what.
      * Now:
         C' = ((S**E mod N) C ) mod N
      * Submit C', which appears totally different from
        C, to the server, recovering P', which appears
        totally different from P
      * Now
                P'
          P = ----- mod N
                S

   Oops!

   Implement that attack.
}
@defclass[UnpaddedRSAServer% object% ()]{

 Represents an instance of a Server using SRP.

 @defconstructor[()]{

  Creates an instance of a server that uses RSA encryption without
  padding. The server allows decryption of a message only once.
 }

 @defmethod[(encrypt [message bytes?]) bytes?]{
  Uses unpadded RSA to encrypt the given message.
}
@defmethod[(decrypt [message bytes?]) bytes?]
  Uses unpadded RSA to decrypt the given message. Only allows a message
  to be decrypted once. If the given message has already been decrypted,
  it throws an error.
}

@defproc[(attack-server [server (is-a UnpaddedRSAServer%)] [msg bytes?]) bytes?]{
  Attacks an @racket[UnpaddedRSAServer%] using the above decribed attack. Should
  return the message that was input into it. 
}

@section{Challenge 42}

@defmodule["set6/c42.rkt"]
 @codeblock{
   RSA with an encrypting exponent of 3 is popular,
   because it makes the RSA math faster.

   With e=3 RSA, encryption is just cubing a number
   mod the public encryption modulus:
      c = m**3 % n

   e=3 is secure as long as we can make assumptions about
   the message blocks we're encrypting. The worry with low-
   exponent RSA is that the message blocks we process won't
   be large enough to wrap the modulus after being cubed.
   The block 00:02 (imagine sufficient zero-padding) can
   be "encrypted" in e=3 RSA; it is simple 00:08.

   When RSA is used to sign, rather than encrypt, the
   operations are reversed; the verifier "decrypts" the
   message by cubing it. This produces a "plaintext"
   which the verifier checks for validity.

   When you use RSA to sign a message, you supply it
   a block input that contains a message digest. The
   PKCS1.5 standard formats that block as:
      00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH

   As intended, the ffh bytes in that block expand to
   fill the whole block, producing a "right-justified"
   hash (the last byte of the hash is the last byte of
   the message)

   There was, 7 years ago, a common implementation flaw
   with RSA verifiers: they'd verify signatures by
   "decrypting" them (cubing them modulo the public
   exponent) and then "parsing" them by looking for
   00h 01h ... ffh 00h ASN.1 HASH.

   This is a bug because it implies the verifier isn't
   checking all the padding. If you don't check the
   padding, you leave open the possibility that instead
   of hundreds of ffh bytes, you have only a few, which
   if you think about it means there could be squizzilions
   of possible numbers that could produce a valid-looking
   signature.

   How to find such a block? Find a number that when cubed
   (a) doesn't wrap the modulus (thus bypassing the key
   entirely) and (b) produces a block that starts
   "00h 01h ffh ... 00h ASN.1 HASH"

   There are two ways to approach this problem:
      * You can work from Hal Finney's writeup,
        available on Google, of how Bleichenbacher
        explained the math "so that you can do it by
        hand with a pencil"
      * You can implement an integer cube root in your
        language, format the message block you want to
        forge, leaving sufficient trailing zeros at the
        end to fill with garbage, then take the cube-root
        of that block.

   Forge a 1024-bit RSA signature for the string "hi mom"

   Make sure your implmentation actually accepts the signature!
}
@defproc[(pkcs15-verify-bad [msg bytes?] [sig bytes?] [pub (cons/c integer? integer?)]) boolean?]{
  Verifies the PKCS1.5 signature for the message using an unsafe verification
  method.
}

@defproc[(forge-sig [msg bytes?]) bytes?]{
  Forges a valid signature for the given @racket[msg] for the bad verification function.
}
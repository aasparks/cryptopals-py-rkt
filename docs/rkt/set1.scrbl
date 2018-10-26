#lang scribble/doc

@(require scribble/manual)

@title[#:tag "set1"]{Set 1}

This is the qualifying set. We picked the exercises in it to
ramp developers up gradually into coding cryptography, but
also to verify that we were working with people who were
ready to write code.

This set is relatively easy. With one exception, most of
these exercises should take only a couple minutes. But
don't beat yourself up if it takes longer than that.
It took Alex two weeks to get through the set!

If you've written any crypto code in the past, you're
going to feel like skipping a lot of this.
Don't skip them. At least two of them (we won't say which)
are important stepping stones to later attacks.

@section{Challenge 1}

@defmodule["set1/c1.rkt"]{
   @codeblock{
   The string:
      49276d206b696c6c696e6720796f757220627261696e206c
      696b65206120706f69736f6e6f7573206d757368726f6f6d

   Should produce:
      SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

   So go ahead and make that happen. You'll need to use this code for
   the rest of the exercises.
   }
   @defproc[(ascii->hex [bstr bytes?]) bytes?]{
   Encodes the ascii byte string into its hex representation.
   }
   @defproc[(hex->ascii [bstr bytes?]) bytes?]{
   Decodes the hex byte string into its ascii representation.
   }
   @defproc[(ascii->base64 [bstr bytes?]) bytes?]{
   Encodes the ascii byte string into its base64 representation.
   }
   @defproc[(base64->ascii [bstr bytes?]) bytes?]{
   Decodes the base64 byte string into its ascii representation.
   }
   @defproc[(hex->base64 [bstr bytes?]) bytes?]{
   Encodes the hex byte string into its base64 representation.
   }
   @defproc[(base64->hex [bstr bytes?]) bytes?]{
   Encodes the base64 byte string into its hex representation.
   }
}

@section{Challenge 2}

@defmodule["set1/c2.rkt"]{
   @codeblock{
   Write a function that takes two equal-length buffers and produces
   their XOR combination.

   If your function works properly, then when you feed it the string:
     1c0111001f010100061a024b53535009181c
   ...after hex decoding, and when XOR'd against:
     686974207468652062756c6c277320657965
   ...should produce
     746865206b696420646f6e277420706c6179
   }
     
   @defproc[(xorstrs [bstr1 bytes?] [bstr2 bytes?]) bytes?]{
   XOR's two byte strings together and returns the result.
   }
}

@section{Challenge 3}

@defmodule["set1/c3.rkt"]{
   @codeblock{
   The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    
   ...has been XOR'd against a single character. Find the key,
   decrypt the message.

   You can do this by hand. But don't: write code to do it for you.
   How? Devise some method for "scoring" a piece of English plaintext.
   Character frequency is a good metric. Evaluate each output and choose
   the one with the best score.
   }
   @defproc[(score [pt bytes?]) integer?]{
   Scores the given plaintext, @racket[pt], from 0-26 using frequency
   analysis.
   }
   @defproc[(single-byte-xor [txt bytes?]) byte?]{
   Returns the key used to encrypt the given ciphertext, @racket[txt],
   under a single byte xor cipher.
   }
}

@section{Challenge 4}

@defmodule["set1/c4.rkt"]{
   @codeblock{
   One of the 60-character strings in this file has been
   encrypted by single-character XOR. Find it.
   }
   @defproc[(detect-single-char-xor [file string?]) bytes?]{
   Given a filename, @racket[file], containing hex-encoded lines,
   finds the line that was encrypted using single character xor and
   returns the decrypted line.
   }
}

@section{Challenge 5}

@defmodule["set1/c5.rkt"]{
   @codeblock{
   Here is the opening stanza of an important work of the
   English language:
   
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal

   Encrypt it, under the key "ICE", using repeating-key XOR.

   In repeating-key XOR, you'll sequentially apply each byte of the key;
   the first byte of plaintext will be XOR'd against I, the next C, the next E,
   then I again for the 4th byte, and so on.

   It should come out to:
   
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

   Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt
   your mail. Encrypt your password file. Your .sig file. Get a feel for it.
   I promise, we aren't wasting your time with this.
   }
   @defproc[(repeat-key [key bytes?] [n integer?]) bytes?]{
   Repeats the given @racket[key] out to a size of @racket[n].
   }
   @defproc[(repeating-key-xor [txt bytes?] [key bytes?]) bytes?]{
   Performs repeating key encryption on the given @racket[txt] by
   repeating the given @racket[key] out to @racket[(bytes-length txt)]
   and XOR'ing the two.
   }
}

@section{Challenge 6}

@defmodule["set1/c6.rkt"]{
   @codeblock{
   There's a file here. It's been base64'd after being
   encrypted with repeating-key XOR.

   Decrypt it.

   Here's how:

      1. Let KEYSIZE be the guessed length of the key.
         try values from 2 to (say) 40.
      2. Write a function to compute the edit distance
         (Hamming distance) between two strings. Hamming
         distance is the number of differing bits.
      3. For each KEYSIZE, take the first KEYSIZE worth of bytes
         and the second KEYSIZE worth of bytes, and find the edit
         distance between them. Normalize this result by dividing
         by KEYSIZE
      4. The KEYSIZE with the smallest normalized edit distance
         is probably the key. You could proceed perhaps with the smallest 2-3
         KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2.
      5. Now that you probably know the KEYSIZE:
         break the ciphertext into blocks of KEYSIZE
         length.
      6. Now transpose the blocks: make a block that is the first
         byte of every block, and a block that is the second byte of every
         block, and so on.
      7. Solve each block as if it was single-character XOR.
      8. For each block, the single-byte XOR key that produces the best looking
         histogram is the repeating-key XOR key byte for that block. Put them
         together and you have the key.

   This code is going to turn out to be surprisingly useful later on. Breaking
   repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
   a "Crypto-101" thing. But more people "know how" to break it than can actually
   break it, and a similar technique breaks something much more important.
   }
    
   @defproc[(hamming-distance [bstr1 bytes?] [bstr2 bytes?]) integer?]{
   Computes the hamming distance between the two given byte strings.
   }
   @defproc[(break-repeating-key [ctxt bytes?]) bytes?]{
   Returns the key used to encrypt the given ciphertext,
   @racket[ctxt], under repeating key XOR.
   }
}

@section{Challenge 7}
   @codeblock{
    The base64-encoded content in this file has been encrypted via
    AES-128 in ECB mode under the key
      "YELLOW SUBMARINE"
    ;(case-sensitive, without the quotes; exactly 16 characters).
    Decrypt it. You know the key, after all.
    }

    The challenge here was to decrypt a file using AES-128 in ECB mode.
    This is provided by the @racket["util/aes.rkt"] module above.

@section{Challenge 8}

@defmodule["set1/c8.rkt"]{
   @codeblock{
   In this file are a bunch of hex-encoded ciphertexts.

   One of them has been encrypted with ECB.

   Detect it.

   Remember that the problem with ECB is that it is
   stateless and deterministic: the same 16-byte
   plaintext block will always produce the same
   16-byte ciphertext.
   }
    
   @defproc[(is-ecb? [txt bytes?]) bytes?]{
   Determines if the given @racket[txt] was encrypted using ECB
   mode.
   }
}

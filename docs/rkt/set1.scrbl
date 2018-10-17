#lang scribble/doc

@(require scribble/manual)

@title{Set 1}

Below are the functions provided by each challenge from Set 1.

@section{Challenge 1}

@defmodule["set1/c1.rkt"]{
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
   @defproc[(xorstrs [bstr1 bytes?] [bstr2 bytes?]) bytes?]{
   XOR's two byte strings together and returns the result.
   }
}

@section{Challenge 3}

@defmodule["set1/c3.rkt"]{
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
   @defproc[(detect-single-char-xor [file string?]) bytes?]{
   Given a filename, @racket[file], containing hex-encoded lines,
   finds the line that was encrypted using single character xor and
   returns the decrypted line.
   }
}

@section{Challenge 5}

@defmodule["set1/c5.rkt"]{
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
   @defproc[(hamming-distance [bstr1 bytes?] [bstr2 bytes?]) integer?]{
   Computes the hamming distance between the two given byte strings.
   }
   @defproc[(break-repeating-key [ctxt bytes?]) bytes?]{
   Returns the key used to encrypt the given ciphertext,
   @racket[ctxt], under repeating key XOR.
   }
}

@section{Challenge 7}

The challenge here was to decrypt a file using AES-128 in ECB mode.
This is provided by the @racket["util/aes.rkt"] module above.

@section{Challenge 8}

@defmodule["set1/c8.rkt"]{
   @defproc[(is-ecb? [txt bytes?]) bytes?]{
   Determines if the given @racket[txt] was encrypted using ECB
   mode.
   }
}

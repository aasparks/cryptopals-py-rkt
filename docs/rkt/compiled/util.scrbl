#lang scribble/doc

@(require scribble/manual
          "../util/mt19937.rkt")
@(require (for-label racket/class))

@title{Utilities}

This module contains all the common utilities that are used by other
modules.

@section{Conversions}

These are conversion functions for bytestrings that are used in almost
every exercise.

@defmodule["util/conversions.rkt"]{
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
   @defproc[(xorstrs [bstr1 bytes?] [bstr2 bytes?]) bytes?]{
   XOR's two byte strings together and returns the result.
   }
}

@section{Hashing}

@subsection{SHA-1}

@defmodule["util/sha1.rkt"]{
   @defproc[(sha1 [bstr bytes?]) bytes?]{
   Returns the SHA-1 digest of the given byte string.
   }
}

@subsection{MD4}

@defmodule["util/md4.rkt"]{
   @defproc[(md4 [bstr bytes?]) bytes?]{
   Returns the MD4 digest of the given byte string.
   }
}

@section{Encryption}

@subsection{AES-128}

@defmodule["util/aes.rkt"]{
   @defproc[(aes-128-encrypt [txt bytes?]
                             [key bytes?]
                             [iv-or-nonce (or/c bytes? integer?) 0]
                             [#:mode mode? symbol? 'ECB]) bytes?]{
    Performs AES-128 encrypt on @racket[txt] under the provided @racket[mode]. Valid
    options for @racket[#:mode] are @racket['ECB], @racket['CBC], or @racket['CTR].
    Lower-case @racket[mode]s are accepted as well (i.e. @racket['ecb]).
    For @racket['CBC] and @racket['CTR] modes, the default @racket[iv] is @racket[(make-bytes 16 0)]
    and the default @racket[nonce] is @racket[0].
}
   @defproc[(aes-128-decrypt [txt bytes?]
                             [key bytes?]
                             [iv-or-nonce (or/c bytes? integer?) 0]
                             [#:mode mode? symbol? 'ECB]) bytes?]{
    Performs AES-128 decrypt on @racket[txt] under the provided @racket[mode]. Valid
    options for @racket[#:mode] are @racket['ECB], @racket['CBC], or @racket['CTR].
    Lower-case @racket[mode]s are accepted as well (i.e. @racket['ecb]).
    For @racket['CBC] and @racket['CTR] modes, the default @racket[iv] is @racket[(make-bytes 16 0)]
    and the default @racket[nonce] is @racket[0].
    }
}

@section{Randomness}

@subsection{Mersenne Twister}

@defmodule["util/mt19937.rkt"]

@defclass[MT19937% object% ()]{

Represents an instance of the Mersenne Twister PRNG.

@defconstructor[([seed integer? random-number]
                 [state vector? default-state])]{

Creates an instance of MT19937 with the provided
@racket[seed] or uses @racket[crypto-random-bytes]
to generate a random seed.

A malicious @racket[state] can be injected at the start
to clone another instance of MT19937. Otherwise the
@racket[default-state] is calculated from the seed.
}

@defmethod[(generate-number) integer?]{
 Generates a random integer 
}}

@subsection{PKCS#7}

@defmodule["util/pkcs7.rkt"]{
   @defproc[(pkcs7-pad [bstr bytes?] [len integer? 16]) bytes?]{
   Pads out the given byte string using PKCS#7 standard.
   }
   @defproc[(pkcs7-unpad [bstr bytes?] [len integer? 16]) bytes?]{
   Unpads the given byte string that was padded with PKCS#7 and
   performs validation.
   }
}

@section{Public Key}

@subsection{Diffie-Hellman}

@defmodule["util/diffie-hellman.rkt"]{
  @defproc[(diffie-hellman [p integer?] [g integer?]) (values integer? integer?)]{
  Computes the Diffie-Hellman private, public (in that order) key pair from
  the provided values for @racket[p] and @racket[g].
 }

  @defproc[(make-session-key [pub integer?] [priv integer?] [p integer?]) bytes?]{
  Creates a session key from the public, private key pair from Diffie-Hellman.
  (Note: the key pairs are B,a and A,b).
 }
}


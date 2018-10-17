#lang scribble/doc

@(require scribble/manual)

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


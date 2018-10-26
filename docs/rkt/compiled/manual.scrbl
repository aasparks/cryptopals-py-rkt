#lang scribble/manual

@title[#:style 'toc]{Cryptopals Racket}

@author{aasparks}

These are my solutions to the Cryptopals challenges. The following
is the API I've created from the solutions. This does not include every function
written, like the Python documents do. This is only the functions that are
@racket{provide}d by each module.

@local-table-of-contents[]

@; ------------------------------------------------------------------------
@include-section["util.scrbl"]
@include-section["set1.scrbl"]
@include-section["set2.scrbl"]
@include-section["set3.scrbl"]
@include-section["set4.scrbl"]
@include-section["set5.scrbl"]

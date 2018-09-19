#lang racket
(require web-server/servlet
         web-server/servlet-env)
(require "c28.rkt"
         "../set1/c1.rkt")

(struct file-req (name sig))

; start: request -> response
; Consumes a request and produces a page that displays all of the
; web content.
(define (start request)
  (define a-file
    (cond [(can-parse-request (request-bindings request))
           (parse-file-req (request-bindings request))]
          [else
           (file-req "No request" "")]))
  (render-file-page a-file request))
 
 
; can-parse-request?: bindings -> boolean
; Produces true if bindings contains values for 'file and 'signature
(define (can-parse-request bindings)
  (and (exists-binding? 'file bindings)
       (exists-binding? 'signature bindings)))
 
; parse-file-req: bindings -> post
; Consumes a bindings, and produces a file-req out of the bindings.
(define (parse-file-req bindings)
  (file-req (extract-binding/single 'file bindings)
            (extract-binding/single 'signature bindings)))
 
; render-blog-page: blog request -> response
; Consumes a blog and a request, and produces an HTML page
; of the content of the blog.
(define (render-file-page a-file request)
  (render-file-req a-file))

; render-file-req : file-req -> xexpr
(define (render-file-req a-file)
  (cond
    [(not (non-empty-string?
      (file-req-sig a-file)))
     (response/xexpr
      `(h3 "No signature")
      #:code 200)]
    [(validate-file-req a-file)
     (response/xexpr
      `(h3 "Good")
      #:code 200)
     ]
    [else
     (response/xexpr
      `(h3 "Bad")
      #:code 500
      #:message #"Error")]))

; validate-file-req : file-req -> xexpr
; validates the file's hmac signature with
; an artificial timing leak
(define (validate-file-req a-file)
  (define fname (file-req-name a-file))
  (define fsig (file-req-sig a-file))
  (define actual-sig
    (bytes->string/utf-8
     (ascii->hex
     (hmac
      (string->bytes/utf-8 fname)))))
  (insecure-compare fsig actual-sig))

; insecure-compare : string string -> boolean
; compares the strings for equality with the
; artificial timing leak put in
(define (insecure-compare s1 s2)
  (when (not (equal? (string-length s1)
                     (string-length s2)))
    #false)
  ; for/and short-circuits so that's good
  (for/and ([i (in-range (string-length s1))])
    (if (equal? (string-ref s1 i)
                (string-ref s2 i))
        (begin
          (sleep 0.5)
          #t)
        #f)))

; TODO: delete this after testing
(printf "~v\n"
        (ascii->hex
         (hmac #"secret.txt")))

(serve/servlet start
               #:port 9000
               #:servlet-path "/file-request")
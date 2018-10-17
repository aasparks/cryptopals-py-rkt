#lang racket

(provide Sbox
         invSbox
         galois-mult-table
         Rcon)


(define Sbox (vector-immutable
              #x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76
              #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0
              #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15
              #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75
              #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84
              #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf
              #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8
              #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2
              #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73
              #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb
              #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79
              #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08
              #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a
              #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e
              #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf
              #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16))

(define invSbox (vector-immutable
                 #x52 #x09 #x6a #xd5 #x30 #x36 #xa5 #x38 #xbf #x40 #xa3 #x9e #x81 #xf3 #xd7 #xfb
                 #x7c #xe3 #x39 #x82 #x9b #x2f #xff #x87 #x34 #x8e #x43 #x44 #xc4 #xde #xe9 #xcb
                 #x54 #x7b #x94 #x32 #xa6 #xc2 #x23 #x3d #xee #x4c #x95 #x0b #x42 #xfa #xc3 #x4e
                 #x08 #x2e #xa1 #x66 #x28 #xd9 #x24 #xb2 #x76 #x5b #xa2 #x49 #x6d #x8b #xd1 #x25
                 #x72 #xf8 #xf6 #x64 #x86 #x68 #x98 #x16 #xd4 #xa4 #x5c #xcc #x5d #x65 #xb6 #x92
                 #x6c #x70 #x48 #x50 #xfd #xed #xb9 #xda #x5e #x15 #x46 #x57 #xa7 #x8d #x9d #x84
                 #x90 #xd8 #xab #x00 #x8c #xbc #xd3 #x0a #xf7 #xe4 #x58 #x05 #xb8 #xb3 #x45 #x06
                 #xd0 #x2c #x1e #x8f #xca #x3f #x0f #x02 #xc1 #xaf #xbd #x03 #x01 #x13 #x8a #x6b
                 #x3a #x91 #x11 #x41 #x4f #x67 #xdc #xea #x97 #xf2 #xcf #xce #xf0 #xb4 #xe6 #x73
                 #x96 #xac #x74 #x22 #xe7 #xad #x35 #x85 #xe2 #xf9 #x37 #xe8 #x1c #x75 #xdf #x6e
                 #x47 #xf1 #x1a #x71 #x1d #x29 #xc5 #x89 #x6f #xb7 #x62 #x0e #xaa #x18 #xbe #x1b
                 #xfc #x56 #x3e #x4b #xc6 #xd2 #x79 #x20 #x9a #xdb #xc0 #xfe #x78 #xcd #x5a #xf4
                 #x1f #xdd #xa8 #x33 #x88 #x07 #xc7 #x31 #xb1 #x12 #x10 #x59 #x27 #x80 #xec #x5f
                 #x60 #x51 #x7f #xa9 #x19 #xb5 #x4a #x0d #x2d #xe5 #x7a #x9f #x93 #xc9 #x9c #xef
                 #xa0 #xe0 #x3b #x4d #xae #x2a #xf5 #xb0 #xc8 #xeb #xbb #x3c #x83 #x53 #x99 #x61
                 #x17 #x2b #x04 #x7e #xba #x77 #xd6 #x26 #xe1 #x69 #x14 #x63 #x55 #x21 #x0c #x7d))

(define galois-mult-table
  (vector-immutable
   (vector-immutable #x00 #x09 #x12 #x1b #x24 #x2d #x36 #x3f #x48 #x41 #x5a #x53 #x6c #x65 #x7e #x77 
                     #x90 #x99 #x82 #x8b #xb4 #xbd #xa6 #xaf #xd8 #xd1 #xca #xc3 #xfc #xf5 #xee #xe7 
                     #x3b #x32 #x29 #x20 #x1f #x16 #x0d #x04 #x73 #x7a #x61 #x68 #x57 #x5e #x45 #x4c 
                     #xab #xa2 #xb9 #xb0 #x8f #x86 #x9d #x94 #xe3 #xea #xf1 #xf8 #xc7 #xce #xd5 #xdc 
                     #x76 #x7f #x64 #x6d #x52 #x5b #x40 #x49 #x3e #x37 #x2c #x25 #x1a #x13 #x08 #x01 
                     #xe6 #xef #xf4 #xfd #xc2 #xcb #xd0 #xd9 #xae #xa7 #xbc #xb5 #x8a #x83 #x98 #x91 
                     #x4d #x44 #x5f #x56 #x69 #x60 #x7b #x72 #x05 #x0c #x17 #x1e #x21 #x28 #x33 #x3a 
                     #xdd #xd4 #xcf #xc6 #xf9 #xf0 #xeb #xe2 #x95 #x9c #x87 #x8e #xb1 #xb8 #xa3 #xaa 
                     #xec #xe5 #xfe #xf7 #xc8 #xc1 #xda #xd3 #xa4 #xad #xb6 #xbf #x80 #x89 #x92 #x9b 
                     #x7c #x75 #x6e #x67 #x58 #x51 #x4a #x43 #x34 #x3d #x26 #x2f #x10 #x19 #x02 #x0b 
                     #xd7 #xde #xc5 #xcc #xf3 #xfa #xe1 #xe8 #x9f #x96 #x8d #x84 #xbb #xb2 #xa9 #xa0 
                     #x47 #x4e #x55 #x5c #x63 #x6a #x71 #x78 #x0f #x06 #x1d #x14 #x2b #x22 #x39 #x30 
                     #x9a #x93 #x88 #x81 #xbe #xb7 #xac #xa5 #xd2 #xdb #xc0 #xc9 #xf6 #xff #xe4 #xed 
                     #x0a #x03 #x18 #x11 #x2e #x27 #x3c #x35 #x42 #x4b #x50 #x59 #x66 #x6f #x74 #x7d 
                     #xa1 #xa8 #xb3 #xba #x85 #x8c #x97 #x9e #xe9 #xe0 #xfb #xf2 #xcd #xc4 #xdf #xd6 
                     #x31 #x38 #x23 #x2a #x15 #x1c #x07 #x0e #x79 #x70 #x6b #x62 #x5d #x54 #x4f #x46)
   (vector-immutable #x00 #x0b #x16 #x1d #x2c #x27 #x3a #x31 #x58 #x53 #x4e #x45 #x74 #x7f #x62 #x69 
                     #xb0 #xbb #xa6 #xad #x9c #x97 #x8a #x81 #xe8 #xe3 #xfe #xf5 #xc4 #xcf #xd2 #xd9 
                     #x7b #x70 #x6d #x66 #x57 #x5c #x41 #x4a #x23 #x28 #x35 #x3e #x0f #x04 #x19 #x12 
                     #xcb #xc0 #xdd #xd6 #xe7 #xec #xf1 #xfa #x93 #x98 #x85 #x8e #xbf #xb4 #xa9 #xa2 
                     #xf6 #xfd #xe0 #xeb #xda #xd1 #xcc #xc7 #xae #xa5 #xb8 #xb3 #x82 #x89 #x94 #x9f 
                     #x46 #x4d #x50 #x5b #x6a #x61 #x7c #x77 #x1e #x15 #x08 #x03 #x32 #x39 #x24 #x2f 
                     #x8d #x86 #x9b #x90 #xa1 #xaa #xb7 #xbc #xd5 #xde #xc3 #xc8 #xf9 #xf2 #xef #xe4 
                     #x3d #x36 #x2b #x20 #x11 #x1a #x07 #x0c #x65 #x6e #x73 #x78 #x49 #x42 #x5f #x54 
                     #xf7 #xfc #xe1 #xea #xdb #xd0 #xcd #xc6 #xaf #xa4 #xb9 #xb2 #x83 #x88 #x95 #x9e 
                     #x47 #x4c #x51 #x5a #x6b #x60 #x7d #x76 #x1f #x14 #x09 #x02 #x33 #x38 #x25 #x2e 
                     #x8c #x87 #x9a #x91 #xa0 #xab #xb6 #xbd #xd4 #xdf #xc2 #xc9 #xf8 #xf3 #xee #xe5 
                     #x3c #x37 #x2a #x21 #x10 #x1b #x06 #x0d #x64 #x6f #x72 #x79 #x48 #x43 #x5e #x55 
                     #x01 #x0a #x17 #x1c #x2d #x26 #x3b #x30 #x59 #x52 #x4f #x44 #x75 #x7e #x63 #x68 
                     #xb1 #xba #xa7 #xac #x9d #x96 #x8b #x80 #xe9 #xe2 #xff #xf4 #xc5 #xce #xd3 #xd8 
                     #x7a #x71 #x6c #x67 #x56 #x5d #x40 #x4b #x22 #x29 #x34 #x3f #x0e #x05 #x18 #x13 
                     #xca #xc1 #xdc #xd7 #xe6 #xed #xf0 #xfb #x92 #x99 #x84 #x8f #xbe #xb5 #xa8 #xa3)
   (vector-immutable #x00 #x0d #x1a #x17 #x34 #x39 #x2e #x23 #x68 #x65 #x72 #x7f #x5c #x51 #x46 #x4b 
                     #xd0 #xdd #xca #xc7 #xe4 #xe9 #xfe #xf3 #xb8 #xb5 #xa2 #xaf #x8c #x81 #x96 #x9b 
                     #xbb #xb6 #xa1 #xac #x8f #x82 #x95 #x98 #xd3 #xde #xc9 #xc4 #xe7 #xea #xfd #xf0 
                     #x6b #x66 #x71 #x7c #x5f #x52 #x45 #x48 #x03 #x0e #x19 #x14 #x37 #x3a #x2d #x20 
                     #x6d #x60 #x77 #x7a #x59 #x54 #x43 #x4e #x05 #x08 #x1f #x12 #x31 #x3c #x2b #x26 
                     #xbd #xb0 #xa7 #xaa #x89 #x84 #x93 #x9e #xd5 #xd8 #xcf #xc2 #xe1 #xec #xfb #xf6 
                     #xd6 #xdb #xcc #xc1 #xe2 #xef #xf8 #xf5 #xbe #xb3 #xa4 #xa9 #x8a #x87 #x90 #x9d 
                     #x06 #x0b #x1c #x11 #x32 #x3f #x28 #x25 #x6e #x63 #x74 #x79 #x5a #x57 #x40 #x4d 
                     #xda #xd7 #xc0 #xcd #xee #xe3 #xf4 #xf9 #xb2 #xbf #xa8 #xa5 #x86 #x8b #x9c #x91 
                     #x0a #x07 #x10 #x1d #x3e #x33 #x24 #x29 #x62 #x6f #x78 #x75 #x56 #x5b #x4c #x41 
                     #x61 #x6c #x7b #x76 #x55 #x58 #x4f #x42 #x09 #x04 #x13 #x1e #x3d #x30 #x27 #x2a 
                     #xb1 #xbc #xab #xa6 #x85 #x88 #x9f #x92 #xd9 #xd4 #xc3 #xce #xed #xe0 #xf7 #xfa 
                     #xb7 #xba #xad #xa0 #x83 #x8e #x99 #x94 #xdf #xd2 #xc5 #xc8 #xeb #xe6 #xf1 #xfc 
                     #x67 #x6a #x7d #x70 #x53 #x5e #x49 #x44 #x0f #x02 #x15 #x18 #x3b #x36 #x21 #x2c 
                     #x0c #x01 #x16 #x1b #x38 #x35 #x22 #x2f #x64 #x69 #x7e #x73 #x50 #x5d #x4a #x47 
                     #xdc #xd1 #xc6 #xcb #xe8 #xe5 #xf2 #xff #xb4 #xb9 #xae #xa3 #x80 #x8d #x9a #x97)
   (vector-immutable #x00 #x0e #x1c #x12 #x38 #x36 #x24 #x2a #x70 #x7e #x6c #x62 #x48 #x46 #x54 #x5a 
                     #xe0 #xee #xfc #xf2 #xd8 #xd6 #xc4 #xca #x90 #x9e #x8c #x82 #xa8 #xa6 #xb4 #xba 
                     #xdb #xd5 #xc7 #xc9 #xe3 #xed #xff #xf1 #xab #xa5 #xb7 #xb9 #x93 #x9d #x8f #x81 
                     #x3b #x35 #x27 #x29 #x03 #x0d #x1f #x11 #x4b #x45 #x57 #x59 #x73 #x7d #x6f #x61 
                     #xad #xa3 #xb1 #xbf #x95 #x9b #x89 #x87 #xdd #xd3 #xc1 #xcf #xe5 #xeb #xf9 #xf7 
                     #x4d #x43 #x51 #x5f #x75 #x7b #x69 #x67 #x3d #x33 #x21 #x2f #x05 #x0b #x19 #x17 
                     #x76 #x78 #x6a #x64 #x4e #x40 #x52 #x5c #x06 #x08 #x1a #x14 #x3e #x30 #x22 #x2c 
                     #x96 #x98 #x8a #x84 #xae #xa0 #xb2 #xbc #xe6 #xe8 #xfa #xf4 #xde #xd0 #xc2 #xcc 
                     #x41 #x4f #x5d #x53 #x79 #x77 #x65 #x6b #x31 #x3f #x2d #x23 #x09 #x07 #x15 #x1b 
                     #xa1 #xaf #xbd #xb3 #x99 #x97 #x85 #x8b #xd1 #xdf #xcd #xc3 #xe9 #xe7 #xf5 #xfb 
                     #x9a #x94 #x86 #x88 #xa2 #xac #xbe #xb0 #xea #xe4 #xf6 #xf8 #xd2 #xdc #xce #xc0 
                     #x7a #x74 #x66 #x68 #x42 #x4c #x5e #x50 #x0a #x04 #x16 #x18 #x32 #x3c #x2e #x20 
                     #xec #xe2 #xf0 #xfe #xd4 #xda #xc8 #xc6 #x9c #x92 #x80 #x8e #xa4 #xaa #xb8 #xb6 
                     #x0c #x02 #x10 #x1e #x34 #x3a #x28 #x26 #x7c #x72 #x60 #x6e #x44 #x4a #x58 #x56 
                     #x37 #x39 #x2b #x25 #x0f #x01 #x13 #x1d #x47 #x49 #x5b #x55 #x7f #x71 #x63 #x6d 
                     #xd7 #xd9 #xcb #xc5 #xef #xe1 #xf3 #xfd #xa7 #xa9 #xbb #xb5 #x9f #x91 #x83 #x8d)))

(define Rcon (vector-immutable
              #x01000000
              #x02000000
              #x04000000
              #x08000000
              #x10000000
              #x20000000
              #x40000000
              #x80000000
              #x1b000000
              #x36000000))
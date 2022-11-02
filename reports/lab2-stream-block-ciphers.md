# Symmetric Ciphers. Stream Ciphers. Block Ciphers

## Course: Cryptography & Security

### Author: Viorel Noroc

----

## Theory

Symmetric Cryptography deals with the encryption of plain text when having only one encryption key which needs to remain private. Based on the way the plain text is processed/encrypted there are 2 types of ciphers:

- Stream ciphers:
  - The encryption is done one byte at a time.
  - Stream ciphers use confusion to hide the plain text.
  - Make use of substitution techniques to modify the plain text.
  - The implementation is fairly complex.
  - The execution is fast.
- Block ciphers:
  - The encryption is done one block of plain text at a time.
  - Block ciphers use confusion and diffusion to hide the plain text.
  - Make use of transposition techniques to modify the plain text.
  - The implementation is simpler relative to the stream ciphers.
  - The execution is slow compared to the stream ciphers. [[1]](#1)

### Stream cipher: Rabbit

Rabbit is a stream cipher algorithm that has been designed for high performance in software implementations.  Both key setup and encryption are very fast, making the algorithm particularly suited for all applications where large amounts of data or large numbers of data packages have to be encrypted.  Examples include, but are not limited to, server-side encryption, multimedia encryption, hard-disk encryption, and encryption on limited-resource devices.

Technically, Rabbit consists of a pseudorandom bitstream generator that takes a 128-bit key and a 64-bit initialization vector (IV) as input and generates a stream of 128-bit blocks.  Encryption is performed by combining this output with the message, using the exclusive-OR operation.  Decryption is performed in exactly the same way as encryption. [[2]](#2)

### Block cipher: Serpent

Serpent is a symmetric key block cipher that was a finalist in the Advanced Encryption Standard (AES) contest. Serpent has a block size of 128 bits and supports a key size of 128, 192 or 256 bits. The cipher is a 32-round substitution–permutation network operating on a block of four 32-bit words. Each round applies one of eight 4-bit to 4-bit S-boxes 32 times in parallel. Serpent was designed so that all operations can be executed in parallel, using 32 bit slices.

Serpent took a conservative approach to security, opting for a large security margin: the designers deemed 16 rounds to be sufficient against known types of attack, but specified 32 rounds as insurance against future discoveries in cryptanalysis.

The Serpent cipher algorithm is in the public domain and has not been patented. The reference code is public domain software and the optimized code is under GPL. There are no restrictions or encumbrances whatsoever regarding its use. As a result, anyone is free to incorporate Serpent in their software (or hardware implementations) without paying license fees.[[3]](#3)[[4]](#4)

## Objectives

1. Get familiar with the symmetric cryptography, stream and block ciphers.

2. Implement an example of a stream cipher (Rabbit).

3. Implement an example of a block cipher (Serpent).

## Conclusions

This laboratory taught me how complex modern ciphers can be. It helped me understand symmetric cryptography, stream and block ciphers on a deeper level than before. The difference between a stream cipher and a block cipher is that stream ciphers encrypt byte by byte and block ciphers encrypt a block of text at a time. This leads to a more complex implementation for stream ciphers but a faster execution, and vice-versa for block ciphers, they are simpler to implement but execution is slower. The implemented ciphers (Rabbit and Serpent) were a good practice for this laboratory work.

## References

### 1

<https://github.com/DrVasile/CS-Labs/blob/master/LaboratoryWork2/laboratoryWork2Task.md>

### 2

<https://www.rfc-editor.org/rfc/rfc4503.html>

### 3

<https://en.wikipedia.org/wiki/Serpent_(cipher)>

### 4

<https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf>
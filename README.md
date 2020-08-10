# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to `keccak` scheme, but is a
completely different implementation of this concept.

PRVHASH is still a proof-of-concept hash function, and is comparably slow,
suitable for short messages only. PRVHASH can generate 32- to 512-bit hashes,
in 32-bit increments, yielding hashes of roughly equal quality independent of
the chosen hash length. PRVHASH is based on 64-bit math. Hashes beyond
256-bits may not pass all the hash tests due to limitations of 64-bit math
used in this hash function, but, for example, any 32-bit element extracted
from 512-bit resulting hash is as collision resistant as just a 32-bit hash.
Extension of the function beyond 512-bit hashes is possible, but has to be
statistically tested (Zeroes or constant-value messages test may fail which
is understandable: no entropy in the message).

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. A simple XOR
checksum of the message can be also supplied, if security considerations
permit this: this improves hash statistics; this allows the pseudo-random
number sequence generated internally, to closely follow the uniform
distribution, yielding more normally-distributed hashes.

PRVHASH can be easily transformed into a stream hash by creating a simple
context structure, and moving its initialization to a separate function. It is
a fixed-time hash function that depends only on message and hash lengths.

32-bit PRVHASH passes all [SMHasher](https://github.com/rurban/smhasher)
tests. 256-bit PRVHASH also passes the Avalanche, DiffDist, Window, and Zeroes
tests (other tests were not performed). Other hash lengths were not
thoroughly tested, but extrapolations can be made. PRVHASH may possess
cryptographic properties, but this is yet to be proven.

Please see the `prvhash4.h` file for details of the implementation (the
`prvhash.h` is an outdated initial version).

On big-endian architectures (ARM) each 32-bit element of the resulting hash
should be endianness-corrected (swapped).

The 32-bit hash of the string `The strict avalanche criterion` is `5a9cbd77`.

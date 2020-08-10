# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence that
correlates with the message to be hashed. Resulting hashes closely follow
normal distribution of bit frequency. PRVHASH is conceptually similar to
`keccak` scheme, but is a completely different implementation of this concept.

PRVHASH is still a proof-of-concept hash function, and it is very slow
(successive multiplication-based without parallel features), suitable for
short messages only. PRVHASH can generate 8- to 256-bit hashes, in
8-bit increments, yielding hashes of roughtly equal quality independent of the
hash length. PRVHASH is based on 32-bit math. Currently, with 32-bit math,
hash function starts to fail beyond 256-bit hash length. PRVHASH can be easily
extended to longer hashes by changing its state variables to 64-bit math,
simultaneously improving quality of 256-bit and shorter hashes.

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. A simple XOR
checksum of the message can be also supplied, if security considerations
permit this: this improves hash statistics; this allows the pseudo-random
number sequence generated internally, to closely follow the uniform
distribution, yielding more normally-distributed hashes.

PRVHASH can be easily transformed into a stream hash by creating a simple
context structure, and moving its initialization to a separate function.

32-bit PRVHASH passes all [SMHasher](https://github.com/rurban/smhasher)
tests. 256-bit PRVHASH also passes the Avalanche and DiffDist tests. Other
hash lengths were not thoroughly tested, but extrapolations can be made.
PRVHASH may possess cryptographic properties, but this was not proven yet.

Please see the `prvhash.h` file for details of the implementation.

# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to `keccak` scheme, but is a
completely different implementation of this concept.

PRVHASH is comparably slow, suitable for short messages only. PRVHASH can
generate 32- to 512-bit hashes, in 32-bit increments, yielding hashes of
roughly equal quality independent of the chosen hash length. PRVHASH is based
on 64-bit math. Hashes beyond 256-bits may not pass all the hash tests due to
limitations of 64-bit math used in this hash function, but, for example, any
32-bit element extracted from 512-bit resulting hash is as collision resistant
as just a 32-bit hash. The use of the function beyond 512-bit hashes is easily
possible, but has to be statistically tested (Zeroes or constant-value message
test may fail which is understandable: no entropy in the message).

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is randomly seeded, this allows hashes of such set to closely
follow the normal distribution. Without the seed, the normality is achieved as
a second-order effect, with the internal random-number generator (the `Seed`)
having a skewed distribution. In practice, the initial hash can be also
randomly seeded, adding useful initial entropy.

32- and 64-bit PRVHASH pass all [SMHasher](https://github.com/rurban/smhasher)
tests. 256-bit PRVHASH also passes the Avalanche, DiffDist, Window, and Zeroes
tests (other tests were not performed). Other hash lengths were not
thoroughly tested, but extrapolations can be made. PRVHASH may possess
cryptographic properties, but this is yet to be proven. One point to note here
is that PRVHASH may produce identical hashes for a message extended with a
varying number of constant bytes. So, a 32-bit hash of a message extended with
e.g. 100 constant bytes may be equal to a hash of the same message extended
with 4000000 constant bytes. This is not related to length-extension attack,
but just a feature of the hash function, meaning that this function is best
used on pre-compressed, maximal entropy, data. Fortunately, the required
number of extension bytes depends on the hash length. In practice, if
pre-compression is not used, it may be useful to end the hashing of the
message with a `bitwise NOT` version of the last byte, as a pseudo-entropy
injection.

PRVHASH can be easily transformed into a stream hash by creating a simple
context structure, and moving its initialization to a separate function. It is
a fixed-time hash function that depends only on message and hash lengths.

Please see the `prvhash42.h` file for details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions).

On big-endian architectures (ARM) each 32-bit element of the resulting hash
should be endianness-corrected (byte-swapped).

The 32-bit hash of the string `The strict avalanche criterion` is `36948d6f`.

The 64-bit hash of the same string is `f9ddaa64b261e3b4`.

## Entropy PRNG ##

32-bit PRVHASH can be also used as a very efficient general-purpose PRNG with
an external entropy source injections (like how the `/dev/urandom` works on
Unix): the 32-bit hash value can be used as a pseudo-random number, spliced
into 4 output bytes each round: this was tested to work well when 8-bit true
entropy injections are done inbetween 4 to 1024 generated random bytes (delay
is also obtained via entropy source). An example generator is implemented in
the `prvrng.h` file: simply call the `prvrng_test()` function.

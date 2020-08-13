# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to `keccak` scheme, but is a
completely different implementation of this concept.

PRVHASH is comparably slow, suitable for short messages only. PRVHASH can
generate 32- to unlimited-bit hashes, in 32-bit increments, yielding hashes of
roughly equal quality independent of the chosen hash length. PRVHASH is based
on 64-bit math. Hashes beyond 256-bits may not pass all the hash tests due to
limitations of 64-bit math used in this hash function, but, for example, any
32-bit element extracted from 512- or 2048-bit resulting hash is as collision
resistant as just a 32-bit hash. The use of the function beyond 512-bit hashes
is easily possible, but has to be statistically tested (Zeroes or
constant-value message test may fail which is understandable: no entropy in
the message). Extension of the hash function to 128-bit math works fine: this
increases its properties exponentially.

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is randomly seeded, this allows hashes of such set to closely
follow the normal distribution. Without the seed, the normality is achieved as
a second-order effect, with the internal random-number generator (the `Seed`)
having a distribution skewed towards triangular distribution. In practice,
the `InitLCG`, `InitSeed` (instead of `SeedXOR`), and initial hash, can all be
randomly seeded (note the bit composition considerations of the `lcg` value),
adding useful initial entropy (64 + 64 + hash length bits of total entropy).

32-, 64- and 128-bit PRVHASH pass all [SMHasher](https://github.com/rurban/smhasher)
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
injection. In author's opinion, this hash function is almost definitely
non-reversible since fixed prime numbers are not used, and due to
non-linearities introduced by bit truncations.

PRVHASH can be easily transformed into a stream hash by creating a simple
context structure, and moving its initialization to a separate function. It is
a fixed-time hash function that depends only on message and hash lengths.

Please see the `prvhash42.h` file for details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions).

On big-endian architectures (ARM) each 32-bit element of the resulting hash
should be endianness-corrected (byte-swapped).

The 32-bit hash of the string `The strict avalanche criterion` is `32184023`.

The 64-bit hash of the same string is `7b20846917dc5b06`.

## Entropy PRNG ##

64-bit PRVHASH can be also used as a very efficient general-purpose PRNG with
an external entropy source injections (like how the `/dev/urandom` works on
Unix): the 64-bit hash value can be used as a pseudo-random number, spliced
into 8 output bytes each round: this was tested to work well when 8-bit true
entropy injections are done inbetween 8 to 2048 generated random bytes (delay
is also obtained via entropy source). An example generator is implemented in
the `prvrng.h` file: simply call the `prvrng_test64()` function. The
`prvrng_test32()` implements the same technique, but with 32-bit hashes, for
comparison purposes.

## Description ##

Here is the author's vision on how the function works (in actuality, coming up
with this solution was accompanied with a lot of trial and error).

    const uint64_t m = MessageByte; // Get 8 bits from the message.
    Seed ^= m; // Add message's entropy to the internal entropy.
    Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
    const uint64_t ph = *(uint32_t*) &Hash[ i ]; // Save the current hash.
    *hc ^= (uint32_t) ( Seed >> 32 ); // Add the internal entropy to the hash.
    Seed ^= ph ^ m; // Add saved hash's and message's entropy to the internal entropy.
	lcg += Seed; // Add the internal entropy to the "lcg" variable (both random). Truncation is possible.

## Optimizations ##

The basic optimized versions of 32-, 64- and 128-bit hashes were implemented
in the `prvhash42opt.h` file. On big-endian architectures the resulting hashes
require byte-swapping.

## Other ##

[Follow me on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

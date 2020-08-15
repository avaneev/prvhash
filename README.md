# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to `keccak` scheme, but is a
completely different implementation of this concept.

PRVHASH can generate 32- to unlimited-bit hashes, yielding hashes of roughly
equal quality independent of the chosen hash length. PRVHASH is based on
64-bit math. Hashes beyond 256-bits still require extensive testing, but, for
example, any 32-bit element extracted from 512- or 2048-bit resulting hash is
as collision resistant as just a 32-bit hash. The use of the function beyond
512-bit hashes is easily possible, but has to be statistically tested. The
extension of the hash function to 128-bit math also works well: this increases
its properties exponentially.

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is randomly seeded, this allows hashes of such set to closely
follow the normal distribution. Without the seed, the normality is achieved as
a second-order effect, with the internal random-number generator (the `Seed`)
having a strong distribution skew towards logarithmic distribution. In
practice, the `InitLCG`, `InitSeed` (instead of `SeedXOR`), and initial hash,
can all be randomly seeded (see the suggestions in `prvhash42.h`), adding
useful initial entropy (`lcg` + `Seed` + `Hash` bits of total entropy).

32-, 64-, 128-, and 256-bit PRVHASH hashes pass all [SMHasher](https://github.com/rurban/smhasher)
tests. Other hash lengths were not thoroughly tested, but extrapolations can
be made. PRVHASH may possess cryptographic properties, but this is yet to be
proven. This function is best used on pre-compressed, maximal entropy, data.
To cope with the cases of sparse entropy, PRVHASH ends the hashing of the
message with the trail of "impossible bytes", as a pseudo-entropy injection.
In author's opinion, this hash function is almost definitely non-reversible
since it does not use fixed prime numbers, and due to non-linearities
introduced by bit truncations.

PRVHASH can be easily transformed into a stream hash by creating a simple
context structure, and moving its initialization to a separate function. It is
a fixed-time hash function that depends only on message length.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions).  The `prvhash82.h` file
implements the same function, but extended to 128-bit math: with some
compilers it is faster than `prvhash42.h`.

On big-endian architectures (ARM), when transmitting hashes between systems,
each hash element of the resulting hash should be endianness-corrected
(byte-swapped).

The prvhash42_32 hash of the string `The strict avalanche criterion` is
`17fc6d3c`.

The prvhash42_64 hash of the same string is `e190ee0e5c876678`.

The prvhash82_64 hash of the same string is `ee1a6bc07b6212d6`.

## Entropy PRNG ##

PRVHASH can be also used as a very efficient general-purpose PRNG with an
external entropy source injections (like how the `/dev/urandom` works on
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
    Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
    const uint64_t ph = *(uint32_t*) &Hash[ i ]; // Save the current hash.
    *hc ^= (uint32_t) ( Seed >> 32 ); // Add the internal entropy to the hash.
    Seed ^= ph ^ m; // Add saved hash's and message's entropy to the internal entropy.
	lcg += Seed; // Add the internal entropy to the "lcg" variable (both random). Truncation is possible.

Without external (message) entropy injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy is introduced, the function "shifts" into unrelated state.
So, it can be said that the function "jumps" between a huge number of
pseudo-random generators. Hash length affects the size of this "generator
space", permitting the function to produce quality hashes for any required
hash length.

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

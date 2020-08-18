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
512-bit hashes is easily possible, but has to be statistically tested.

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating HMACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is given a random seed, this allows hashes of such set to closely
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
message with the trail of "impossible words", as a pseudo-entropy injection.
In author's opinion, this hash function is almost definitely non-reversible
since it does not use fixed prime numbers, and due to non-linearities
induced by bit truncations.

PRVHASH can be easily transformed into a streaming hash by creating a simple
context structure, and moving its initialization to a separate function. It is
a fixed execution time hash function that depends only on message length.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions).

The prvhash42_32 hash of the string `The strict avalanche criterion` is
`d2b7e541`.

The prvhash42_64 hash of the same string is `074c0781032e633d`.

## Entropy PRNG ##

PRVHASH can be also used as a very efficient general-purpose PRNG with an
external entropy source injections (like how the `/dev/urandom` works on
Unix): the 64-bit hash value can be used as a pseudo-random number, spliced
into 8 output bytes each round: this was tested, and works well when 8-bit
true entropy injections are done inbetween 8 to 2048 generated random bytes
(delay is also obtained via entropy source). An example generator is
implemented in the `prvrng.h` file: simply call the `prvrng_test64()`
function. The `prvrng_test32()` implements the same technique, but with
32-bit hashes, for comparison purposes.

On a side note, PRVHASH PRNG with 32-bit hashes, without external
entropy injections: after 1.1 trillion iterations the internal pseudo-entropy
was not lost.

## Description ##

Here is the author's vision on how the core hash function works (in actuality,
coming up with this solution was accompanied with a lot of trial and error).

	Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
	uint32_t* const hc = (uint32_t*) &Hash[ hpos ]; // Take the address of the hash word.
	const uint64_t ph = *hc; // Save the current hash word. For entropy feedback.
	const uint64_t ient = Seed >> 32; // Extract internal entropy.
	*hc ^= (uint32_t) ient; // Add the internal entropy to the hash word.
	Seed ^= ph ^ ient ^ msgw; // Mix internal entropy with itself, hash word's and message's entropy.
	lcg += Seed; // Add the internal entropy to the "lcg" variable (both random). Truncation is possible.

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random number generators. Hash
length affects the size of this "space of generators", permitting the function
to produce quality hashes for any required hash length.

How does it work? First of all, this PRNG system, represented by the hash
function, does not work with numbers in a common sense: it works with entropy,
or a random sequence of bits. The current "expression" of system's overall
internal entropy - the `Seed` - gets multiplied ("smeared") by a supportive
variable - `lcg`, - which is also a random value. Such multiplication changes
the `Seed` into a logarithmic-like distribution, de-correlating (in
distribution sense) its lower and higher 32-bit parts. The lower 32 bits of
the `Seed` are then updated by a mix of its own higher 32 bits, the hash word
produced on previous rounds, and the message. The reason the message's entropy
(which may be sparse or non-random) does not destabilize the system is because
the message becomes hidden in a mix of internal and hash word's entropy,
message's distribution becomes irrelevant. Mixing with the hash word also
partly restores normal distribution of `Seed`s lower 32 bits. While the
message "shifts" the system into a new state, predictated by previous
messages. Thus, it is possible to give names to random number generators: for
example, pass a word "Michelle" to the hashing function, and then the
generation will continue in the space predictated by this initial word. Every
bit of entropy matters.

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

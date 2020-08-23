# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a pseudo-random number sequence
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to `keccak` and `RadioGatun`
schemes, but is a completely different implementation of such concept.
PRVHASH is both a ["randomness extractor"](https://en.wikipedia.org/wiki/Randomness_extractor)
and an "extendable-output function".

PRVHASH can generate 32- to unlimited-bit hashes, yielding hashes of roughly
equal quality independent of the chosen hash length. PRVHASH is based on
64-bit math. Hashes beyond 256-bits still require extensive testing, but, for
example, any 32-bit element extracted from 512- or 2048-bit resulting hash is
as collision resistant as just a 32-bit hash. The use of the function beyond
512-bit hashes is easily possible, but has to be statistically tested. It is
a fixed execution time hash function that depends only on message length. A
streamed hashing implementation is available.

PRVHASH is solely based on the butterfly effect, strongly inspired by LCG
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating (H)MACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is given a random seed, this allows hashes of such set to
closely follow the normal distribution. Without the seed, the normality of a
set is achieved as a second-order effect, with the internal random-number
generator (the `Seed`) having a strong distribution skew towards logarithmic
distribution. In practice, the `InitLCG`, `InitSeed` (instead of `SeedXOR`),
and initial hash, can all be randomly seeded (see the suggestions in
`prvhash42.h`), adding useful initial entropy (`lcg` + `Seed` + `Hash` bits of
total entropy).

32-, 64-, 128-, and 256-bit PRVHASH hashes pass all [SMHasher](https://github.com/rurban/smhasher)
tests. Other hash lengths were not thoroughly tested, but extrapolations can
be made. PRVHASH may possess cryptographic properties, but this is yet to be
proven. This function is best used on pre-compressed, maximal entropy, data.
To cope with the cases of sparse entropy, PRVHASH ends the hashing of the
message with the trail of `bitwise NOT` version of the final byte, as a
pseudo-entropy injection. In author's opinion, this hash function is almost
definitely irreversible as it does not use fixed prime numbers, has
non-linearities induced by bit truncations, and because the message enters the
system only as a mix with the system's internal entropy, without permutations
of any sort.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions).

The default prvhash42 32-bit hash of the string `The strict avalanche
criterion` is `dac72cb1`.

The default prvhash42 64-bit hash of the same string is `f7ac47b10d2762fb`.

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

`prvrng_gen64()`-based generator passes `PractRand` 8 TB threshold, without or
with only a few "unusual" evaluations. Which suggests it's the first working
universal TRNG in the world. This claim requires a lot more evaluations from
independent researchers.

On a side note, after 1.1 trillion iterations the internal pseudo-entropy
was not lost in PRVHASH PRNG with 32-bit hashes, without external entropy
injections.

## Streamed Hashing ##

The file `prvhash42s.h` implements a relatively fast streamed hashing
function by utilizing a parallel `prvhash42` structure. Please take a look
at the `prvhash42s_oneshot()` function for usage example. The `prvhash42s`
offers an extremely increased security and hashing speed. The amount of
entropy mixing going on in this implementation is substantial.

The default prvhash42s 256-bit hash of the string
`The quick brown fox jumps over the lazy dog` is
`b7de62b441f983793a98bc267b5b811732090564e8301a4b8cd193d9e5ea13ac`.

The default prvhash42s 256-bit hash of the string
`The quick brown fox jumps over the lazy dof` is
`ef04be381b9f45589d20549dc062fd0ad275de14d87d170193fe6c1b71e99968`.
Which demonstrates the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect):
129 bits are different. On a set of 216553 English words, pair-wise hash
comparisons give average 50.0% difference in resulting hash bits, which fully
satisfies the strict avalanche criterion.

The default prvhash42s 64-bit hash of the string `The strict avalanche
criterion` is `1e144ffccd0714db`.

This streamed hash function produces hash values that are different to the
`prvhash42` hash function. It is incorrect to use both of these hash function
implementations on the same data set. While the `prvhash42` can be used as
a fast hashmap/table hash, it is not so fast on large data blocks. The
`prvhash42s` can be used to create hashes of large data blocks like files.

## Description ##

Here is the author's vision on how the core hash function works. In actuality,
coming up with this solution was accompanied with a lot of trial and error.
It was especially hard to find a better "hashing finalization" solution.

	Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
	uint32_t* const hc = (uint32_t*) &Hash[ hpos ]; // Take the address of the hash word.
	const uint64_t ph = *hc ^ ( Seed >> 32 ); // Mix hash word with the internal entropy.
	Seed ^= ph ^ msgw; // Mix the internal entropy with hash word's and message's entropy. Entropy feedback.
	*hc = (uint32_t) ph; // Store the updated hash word.
	lcg += Seed + msgw2; // Mix in the internal entropy, and an additional message. Truncation is possible.

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random number generators. Hash
length affects the size of this "space of generators", permitting the function
to produce quality hashes for any required hash length.

How does it work? First of all, this PRNG system, represented by the hash
function, does not work with numbers in a common sense: it works with entropy,
or random sequences of bits. The current "expression" of system's overall
internal entropy (which is almost uniformly-random) - the `Seed` - gets
multiplied ("smeared") by a supportive variable - `lcg`, - which is also a
random value. Such multiplication changes the `Seed` into a logarithmic-like
distribution, dividing (in distribution sense) its lower and higher 32-bit
parts. The lower 32 bits of the `Seed` are then updated by a mix of its own
higher 32 bits, the hash word produced on previous rounds, and the message.
The reason the message's entropy (which may be sparse or non-random) does not
destabilize the system is because the message becomes hidden in a mix of
internal and hash word's entropy; message's distribution becomes irrelevant.
The message "shifts" the system into a new state, predictated by previous
messages. Mixing the `Seed` with the hash word partly restores the normal
distribution of `Seed`'s and `lcg`'s lower 32 bits. Iterative mixing of the
hash words with the `Seed` assures that the resulting hashes follow normal
distribution and uniformity, irrespective of the distribution anomalies of
the `Seed` itself.

With PRVHASH it is possible to give names to random number generators: for
example, pass a word "Michelle" to the hashing function, and then the
generation will continue in the space predictated by this initial word. Every
bit of entropy matters.

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

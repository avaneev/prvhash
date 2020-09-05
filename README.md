# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a [pseudo-random number sequence](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
derived from the message. Resulting hashes closely follow normal distribution
of bit frequency. PRVHASH is conceptually similar to [`keccak`](https://en.wikipedia.org/wiki/SHA-3)
and [`RadioGatun`](https://en.wikipedia.org/wiki/RadioGat%C3%BAn)
schemes, but is a completely different implementation of such concept.
PRVHASH is both a ["randomness extractor"](https://en.wikipedia.org/wiki/Randomness_extractor)
and an "extendable-output function" (XOF), however the resulting hashes have
[security level](https://en.wikipedia.org/wiki/Security_of_cryptographic_hash_functions)
that corresponds to the hash length specification: the collision resistance is
equal to `2^(n/2)` while the preimage resistance is equal to `2^n`, where `n`
is the resulting hash length.

PRVHASH can generate 32- to unlimited-bit hashes, yielding hashes of roughly
equal quality independent of the chosen hash length. PRVHASH is based on
64-bit math. The use of the function beyond 512-bit hashes is easily possible,
but has to be statistically tested. For example, any 32-bit element extracted
from 1024-, 2048-, or 4096-bit resulting hash is as collision resistant as
just a 32-bit hash. It is a fixed execution time hash function that depends
only on message length. A streamed hashing implementation is available.

PRVHASH is solely based on the butterfly effect, strongly inspired by [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator)
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating (H)MACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is given a random seed, this allows hashes of such set to
closely follow the normal distribution. Without the seed, the normality of a
set is achieved as a second-order effect, with the internal random-number
generator (the `Seed`) having a strong distribution skew towards logarithmic
distribution. In practice, the `InitVec` (instead of `SeedXOR`), and initial
hash, can both be randomly seeded (see the suggestions in `prvhash42.h`),
adding useful initial entropy (`InitVec` and `Hash` bits of overall entropy).

32-, 64-, 128-, 160-, 256- and 512-bit PRVHASH hashes pass all [SMHasher](https://github.com/rurban/smhasher)
tests. Other hash lengths were not thoroughly tested, but extrapolations can
be made. PRVHASH possesses most of the cryptographic properties, but this
aspect has yet to be better proven. This function is best used on
pre-compressed, maximal-entropy, data. To cope with the cases of sparse
entropy, PRVHASH ends the hashing of the message with the trail of
`bitwise NOT` version of the final byte, as a pseudo-entropy injection. In
author's opinion, this hash function is provably [irreversible](https://en.wikipedia.org/wiki/One-way_function)
as it does not use fixed prime numbers, its output depends on all prior input,
the function has non-linearities (loss of state information) induced by bit
truncations, and because the message enters the system only as a mix with the
system's internal entropy without permutations of any sort. Additionally,
the very first `Seed *= lcg` instruction is hard to reverse: `Seed /= lcg`
cannot be used for inversion directly since `Seed` is truncated, and `lcg` is
usually not a prime number (probabilistically, `lcg` may be a prime in 2.2% of
rounds): with some probability, several solutions are possible.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions). Note that `42` refers to
the core hash function's version (4-byte hash word, version 2).

The default `prvhash42.h`-based 32-bit hash of the string `The strict
avalanche criterion` is `dac72cb1`.

The default `prvhash42.h`-based 64-bit hash of the same string is
`f7ac47b10d2762fb`.

A proposed short name for hashes created with `prvhash42.h` is `PRH42-N`,
where `N` is the hash length in bits (e.g. `PRH42-256`).

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

`prvrng_gen64()`-based generator passes [`PractRand`](http://pracrand.sourceforge.net/)
32 TB threshold, without or with only a few "unusual" evaluations. Which
suggests it's the first working universal TRNG in the world. This claim
requires a lot more evaluations from independent researchers.

On a side note, after 1.1 trillion iterations the internal pseudo-entropy
was not lost in PRVHASH PRNG with 32-bit hashes, without external entropy
injections. Generally speaking, the probability of losing entropy is
negligible while with external entropy injections this probability is zero
(the `lcg` variable is an accumulator of entropy).

## Streamed Hashing ##

The file `prvhash42s.h` implements a relatively fast streamed hashing
function by utilizing a parallel `prvhash42` structure. Please take a look
at the `prvhash42s_oneshot()` function for usage example. The `prvhash42s`
offers an extremely increased security and hashing speed. The amount of
entropy mixing going on in this implementation is substantial.

The default `prvhash42s.h`-based 64-bit hash of the string `The strict
avalanche criterion` is `6f9bfd7b15ac85ee`.

The default `prvhash42s.h`-based 256-bit hash of the string
`The quick brown fox jumps over the lazy dog` is
`15686a68c01f2e1843509d51d3660d1d92be4c19fbc465819af9fb619ba0e99d`
(Shannon entropy index is 3.78).

The default prvhash42s 256-bit hash of the string
`The quick brown fox jumps over the lazy dof` is
`aef1709da356f2b1e1e490e498c1329e0880e7d3d4a28a2aa49f17f44882b7b9`
(Shannon entropy index is 3.83).

This demonstrates the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).
On a set of 216553 English words, pair-wise hash comparisons give average
50.0% difference in resulting hash bits, which fully satisfies the strict
avalanche criterion.

This streamed hash function produces hash values that are different to the
`prvhash42` hash function. It is incorrect to use both of these hash function
implementations on the same data set. While the `prvhash42` can be used as
a fast hashmap/table hash, it is not so fast on large data blocks. The
`prvhash42s` can be used to create hashes of large data blocks like files.

A proposed short name for hashes created with `prvhash42s.h` is `PRH42S-N`,
where `N` is the hash length in bits (e.g. `PRH42S-256`).

## Use As A Stream Cipher ##

The core hash function can be used as a [stream cipher](https://en.wikipedia.org/wiki/Stream_cipher)
if the message is used as a state variable, repeatedly hashed, possibly with
an embedded counter, nonce and key. The resulting output can then be used in
varying quantities as an entropy to hide (XOR) the ciphered message. Ciphering
with a known initial state may need to bypass several initial hashing rounds
for the function to "settle down". The state variable's size may need to be
chosen in a way so that it is not a multiple of hash length.

## Description ##

Here is the author's vision on how the core hash function works. In actuality,
coming up with this solution was accompanied with a lot of trial and error.
It was especially hard to find a better "hashing finalization" solution.

	Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
	uint32_t* const hc = (uint32_t*) &Hash[ hpos ]; // Take the address of the hash word.
	const uint64_t ph = *hc ^ ( Seed >> 32 ); // Mix hash word with the internal entropy (truncated).
	Seed ^= ph ^ msgw; // Mix the internal entropy with hash word's and message's entropy. Entropy feedback.
	*hc = (uint32_t) ph; // Store the updated hash word.
	lcg += Seed + msgw2; // Mix in the internal entropy, and an additional message. Truncation is possible.

An optional variant of the first instruction which eliminates prime numbers
at the cost of some speed (it works only if `msgw2` is not used). It
complicates the function reversal:

	Seed *= lcg + ( lcg & 1 );

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random number generators. Hash
length affects the size of this "space of generators", permitting the function
to produce quality hashes for any required hash length.

How does it work? First of all, this PRNG system, represented by the core hash
function, does not work with numbers in a common sense: it works with [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)),
or uniformly-random sequences of bits. The current "expression" of system's
overall internal entropy (which is almost uniformly-random with a few
anomalies) - the `Seed` - gets multiplied ("smeared") by a supportive
variable - `lcg`, - which is also a similar random value. Such multiplication
changes the `Seed` into a logarithmic-like distribution, dividing (in
distribution sense) its lower and higher 32-bit parts. The lower 32 bits of
the `Seed` are then updated by a mix of its own higher 32 bits, the hash word
produced on previous rounds, and the message. The reason the message's entropy
(which may be sparse or non-random) does not destabilize the system is because
the message becomes hidden in a mix of internal and hash word's entropy;
message's distribution becomes irrelevant. The message "shifts" the system
into a new state, predictated by previous messages. Mixing the `Seed` with the
hash word partly restores the normal distribution of `Seed`'s and `lcg`'s
lower 32 bits. Iterative mixing of the hash words with the `Seed` assures that
the resulting hashes follow normal distribution and uniformity, irrespective
of the distribution anomalies of the `Seed` itself. The `Seed` and `lcg`
variables work in tandem, with each variable able to independently absorb up
to 32 bits of external (message) entropy. Note that `lcg` being an accumulator
quickly leaves a possible zero state.

With PRVHASH it is possible to give names to random number generators: for
example, pass a word "Michelle" to the core hash function, and then the
generation will continue in the space predictated by this initial word. Every
bit of entropy matters.

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a [uniform pseudo-random number
sequence](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
derived from the message. PRVHASH is conceptually similar to [`keccak`](https://en.wikipedia.org/wiki/SHA-3)
and [`RadioGatun`](https://en.wikipedia.org/wiki/RadioGat%C3%BAn)
schemes, but is a completely different implementation of such concept.
PRVHASH is both a ["randomness extractor"](https://en.wikipedia.org/wiki/Randomness_extractor)
and an "extendable-output function" (XOF), however the resulting hashes have
[security level](https://en.wikipedia.org/wiki/Security_of_cryptographic_hash_functions)
that corresponds to the hash length specification: the collision resistance is
equal to `2^(n/2)` while the preimage resistance is equal to `2^n`, where `n`
is the resulting hash length in bits.

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
have a greater statistical distance from each other. In practice, the
`InitVec` (instead of `SeedXOR`), and initial hash, can both be randomly
seeded (see the suggestions in `prvhash42.h`), adding useful initial entropy
(`InitVec` plus `Hash` total bits of entropy).

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
rounds): with considerable probability, several solutions are possible.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions). Note that `42` refers to
the core hash function's version (4-byte hash word, version 2).

The default `prvhash42.h`-based 32-bit hash of the string `The strict
avalanche criterion` is `a704a1b3`.

The default `prvhash42.h`-based 64-bit hash of the same string is
`64cf24c1e0af931f`.

A proposed short name for hashes created with `prvhash42.h` is `PRH42-N`,
where `N` is the hash length in bits (e.g. `PRH42-256`).

## Entropy PRNG ##

PRVHASH can be also used as a very efficient general-purpose PRNG with an
external entropy source injections (like how the `/dev/urandom` works on
Unix): the 64-bit hash value can be used as a pseudo-random number spliced
into 8 output bytes each round: this was tested, and works well when 8-bit
true entropy injections are done inbetween 8 to 2048 generated random bytes
(delay is also obtained via entropy source). An example generator is
implemented in the `prvrng.h` file: simply call the `prvrng_test64p2()`
function.

`prvrng_gen64p2()`-based generator passes [`PractRand`](http://pracrand.sourceforge.net/)
32 TB threshold, without or with only a few "unusual" evaluations. Which
suggests it's the first working universal TRNG in the world. This claim
requires a lot more evaluations from independent researchers.

On a side note, after 1.1 trillion iterations the internal pseudo-entropy
was not lost in PRVHASH PRNG with 32-bit hashes, without external entropy
injections. Generally speaking, the probability of completely "stopping" is
absent due to the structure of the core hash function.

This function, without external entropy injections, with any initial
combination of `lcg`, `Seed`, and `Hash` eventually converges into one of
random number sub-sequences. These are mostly time-delayed versions of only a
smaller set of unique sequences. There are structural limits in this PRNG
system which can be easily reached if there is only a small number of hash
words in the system. PRNG will produce non-repeating random sequences with
external entropy injections, but their statistical quality will be limited by
the size of `lcg` and `Seed` variables, and the number of hash words in the
system. A good property of this PRNG is that when there are several hash words
in the system, each hash word has some structural distance from each other.
For example, if there are 8 hash words in the system, the structural distance
between hash word 0 and hash word 4 (1 and 5, etc.) is maximal. So, hash words
0 and 4 (1 and 5, etc.) can be XORed to produce a larger random structure.
Generally speaking, it is incorrect to use every hash word as a random
output: two structurally distant hash words should be XORed. When there are
only 2 hash words in the system, it is however more practical to use every
hash word as a random sequence as the structural distance between two hash
words is minimal. Another way to increase the structural limit is to use a
parallel PRNG structure demonstrated in the `prvhash42s.h` file, which
additionally increases the security exponentially.

Note that when initally or at some point the `lcg` value is zero, this PRNG
initiates a self-starting sequence, due to discontinuity. It is mathematically
obvious that in this case the function becomes completely irreversible:
`Seed /= lcg` is incalculable when `lcg` is equal to 0. With external entropy
injections or when PRNG is used in the arrangement outlined above (XOR of two
distant hash words), with many hash words in the system, the detection of
self-starting sequence becomes improbable. Admittedly, the existence of such
self-starting sequence is one of the most questionable aspects of this PRNG
system. On the other hand, the self-starting sequence can be avoided by adding
any non-zero random value to `lcg` the moment `lcg` reaches zero state, or
injecting a message entropy via `Seed`. According to `PractRand` tests, both
approaches are good solutions to this nuance; moreover, this is structurally
correct (both `Seed` and `lcg` can accept external entropy).

While `lcg`, `Seed`, and `Hash` variables should be initialized with good
entropy source, the message can be sparsely-random: even an increasing counter
with prime period can be considered as having a suitable sparse entropy.

Since both internal variables (`Seed` and `lcg`) interact with the output
only indirectly (XOR operation with further truncated multiplication), the
PRNG has a high level of security: it is not enough to know the output of PRNG
to predict its future values.

## Streamed Hashing ##

The file `prvhash42s.h` implements a relatively fast streamed hashing
function by utilizing a parallel `prvhash42` structure. Please take a look
at the `prvhash42s_oneshot()` function for usage example. The `prvhash42s`
offers an extremely increased security and hashing speed. The amount of
entropy mixing going on in this implementation is substantial.

The default `prvhash42s.h`-based 64-bit hash of the string `The strict
avalanche criterion` is `e2df0585ca4b46e1`.

The default `prvhash42s.h`-based 256-bit hash of the string
`The quick brown fox jumps over the lazy dog` is
`9cf889bbdb5546589227f524c7186e02f3b1a3f8670f919d2bed20de4f0afd14`
(Shannon entropy index is 3.91).

The default prvhash42s 256-bit hash of the string
`The quick brown fox jumps over the lazy dof` is
`4d56dfeb6d6edb5d1bf4d1a5bf18ddcaeb52cd368097466f4e1dfc35f7729444`
(Shannon entropy index is 3.77).

This demonstrates the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).
On a set of 216553 English words, pair-wise hash comparisons give average
50.0% difference in resulting hash bits, which fully satisfies the strict
avalanche criterion.

This streamed hash function produces hash values that are different to the
`prvhash42` hash function. It is incorrect to use both of these hash function
implementations on the same data set. While the `prvhash42` can be used as
a fast table hash, it is not so fast on large data blocks. The `prvhash42s`
can be used to create hashes of large data blocks like files.

A proposed short name for hashes created with `prvhash42s.h` is `PRH42S-N`,
where `N` is the hash length in bits (e.g. `PRH42S-256`).

## Use As A Stream Cipher ##

The core hash function can be used as a [stream cipher](https://en.wikipedia.org/wiki/Stream_cipher)
if the message is used as a state variable, repeatedly hashed, possibly with
an embedded counter, nonce and key. The resulting output can then be used in
varying quantities as an entropy to hide (XOR) the ciphered message. Ciphering
with a known initial state may need to bypass several initial hashing rounds
for the function to "settle down".

## Description ##

Here is the author's vision on how the core hash function works. In actuality,
coming up with this solution was accompanied with a lot of trial and error.
It was especially hard to find a better "hashing finalization" solution.

	Seed *= lcg; // Multiply random by random. Non-linearity induced due to truncation.
	Seed = ~Seed; // An auxiliary instruction that eliminates entropy loss.
	uint32_t* const hc = (uint32_t*) &Hash[ hpos ]; // Take the address of the hash word.
	const uint64_t hl = lcg >> 32 ^ msgw; // Extract the higher bits of "lcg" and mix with the message.
	lcg += Seed; // Mix in the internal entropy. Truncation is possible.
	lcg += msgw2; // Mix in an additional (optional) message. Truncation is possible.
	const uint64_t ph = *hc ^ ( Seed >> 32 ); // Mix hash word with the internal entropy (truncated).
	Seed ^= ph ^ hl; // Mix the internal entropy with hash word's and message's entropy. Entropy feedback.
	*hc = (uint32_t) ph; // Store the updated hash word.

(This core function can be arbitrarily scaled to any even-size variables:
6-, 8-, 10-, 12-, 16-, 32-, 64-, 128-bit variable sizes were tested, with
similar statistical results).

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random sub-sequences. Hash
length affects the size of this "space of sub-sequences", permitting the
function to produce quality hashes for any required hash length.

How does it work? First of all, this PRNG system, represented by the core hash
function, does not work with numbers in a common sense: it works with [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)),
or random sequences of bits. The current "expression" of system's overall
internal entropy - the `Seed` - gets multiplied ("smeared") by a supportive
accumulator variable - `lcg`, - which is also a random value. Such
multiplication changes the `Seed` into a logarithmic-like distribution,
dividing (in distribution sense) its lower and higher parts. The lower bits of
the `Seed` are then updated by a mix of its own higher bits, `lcg`'s higher
bits, the hash word produced on previous rounds, and the message. The reason
the message's entropy (which may be sparse or non-random) does not destabilize
the system is because the message becomes hidden in a mix of internal and hash
word's entropy; message's distribution becomes irrelevant. The message
"shifts" the system into a new state, predictated by previous messages. Mixing
the `Seed` with the hash word partly restores the uniform distribution of
`Seed`'s lower bits. Iterative mixing of the hash words with the `Seed`
assures that the resulting hashes follow uniform distribution, irrespective of
the distribution anomalies of the `Seed` itself. The `Seed` and `lcg`
variables work in tandem, with each variable able to independently absorb up
to hash word bit size of external (message) entropy (structurally, `Seed`
accepts higher bits of the message while `lcg` accepts lower bits of the
message).

Note that `lcg` being an accumulator quickly leaves a possible zero state.
Injecting (adding) a priorly unknown message via the `lcg` variable requires a
larger variable size: e.g. with 16-bit variable's size (and 8-bit hash word)
this may not work very well due to double truncations: continously adding a
constant will reduce random structure limit by 1-2 bits; on the other hand,
adding an increasing 8-bit counter to 16-bit `lcg` actually increases random
structure limit by 1-2 bits (any non-constant entropy usually maximizes this
limit). With 64-bit variables there should be no practical issues by injecting
entropy via the `lcg` variable. However, if possible, it is more predictable
to inject entropy via the `Seed` variable.

In essence, the hash function generates a continuous pseudo-random number
sequence, and returns the final part of the sequence as a result. The message
acts as a "pathway" to this final part. So, the random sequence of numbers can
be "programmed" to produce a neccessary outcome.

Here is the example of 8 independent (less than 0.027 mutual correlation)
random number sequences that were "programmed" via entropy injections to
produce the required values every 8 bytes ("PRVH"), with Shannon entropy
index:

	1dde74d0e383d8506c24fd7c43a56852748f3e9cc2085d5684f006524884fa48 (3.71)
	fed79113e0e2a250cd647b13fcee6f52b006d86f2c955056d37942b583933048 (3.91)
	a3395c35efea20502415647a1247895291dc64a09f89a756f54b284b85310348 (3.84)
	edd9aceb80e1845042d26a1069b775525696a2d1e8051f56d1ec98f541ff5948 (3.81)
	02bbb8578c1bf450d20e8e3dbeb85f522e64d80746a01756e29aa307363d6048 (3.85)
	e3fdce1636803150c4e483a434aa0d529af3ed01ef9daf562361e4c4cb3c0048 (3.76)
	48510c5f907a2f5017d43fbdab670d52995de67c79920856c67e3c96baa5ac48 (3.89)
	98408dbb35cea250c41d85a229e2ec521ae0ef016fa87d56ac44c1a66d505848 (3.83)

Obviously, this example does not scale well with sequence length, such
"coarse" programming can be easily detected, but it passes `PractRand`'s 1KB
threshold without fail.

However, as this PRNG does not expose its momentary internal state, such
"programming" is hardly possible to perform for an attacker, even if the
entropy input channel is exposed.

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

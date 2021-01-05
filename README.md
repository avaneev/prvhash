# PRVHASH - Pseudo-Random-Value Hash #

## Introduction ##

PRVHASH is a hash function that generates a [uniform pseudo-random number
sequence](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
derived from the message. PRVHASH is conceptually similar (in the sense of
using a pseudo-random number sequence as a hash) to [`keccak`](https://en.wikipedia.org/wiki/SHA-3)
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

PRVHASH is solely based on the butterfly effect, inspired by [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator)
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
aspect has yet to be better proven.

In author's opinion, this hash function is provably [irreversible](https://en.wikipedia.org/wiki/One-way_function)
as it does not use fixed prime numbers, its output depends on all prior input,
the function has non-linearities (loss of state information) induced by bit
truncations, and because the message enters the system only as a mix with the
system's internal entropy without permutations of any sort. This reasoning
applies to the case when internal state of the hashing system is known.
However, if the core hash function is a black-box, and only its output (`out`)
is known, it reveals no information about its prior or later state: all
elements of the core hash function (`Seed`, `lcg`, `out`, `Hash`) are
mutually-uncorrelated and wholly-unequal during the PRNG period. In this case,
the core hash function has the security level that is equal to its full bit
size.

Please see the `prvhash42.h` file for the details of the implementation (the
`prvhash.h` and `prvhash4.h` are outdated versions). Note that `42` refers to
the core hash function's version (4-byte hash word, version 2).

The default `prvhash42.h`-based 32-bit hash of the string `The cat is out of
the bag` is `a0d175de`.

The default `prvhash42.h`-based 64-bit hash of the same string is
`72ca96f954301401`.

A proposed short name for hashes created with `prvhash42.h` is `PRH42-N`,
where `N` is the hash length in bits (e.g. `PRH42-256`).

## Entropy PRNG ##

PRVHASH can be also used as a very efficient general-purpose PRNG with an
external entropy source injections (like how the `/dev/urandom` works on
Unix): this was tested, and works well when 8-bit true entropy injections are
done inbetween 4 to 1024 generated random bytes (delay is also obtained via
the entropy source). An example generator is implemented in the `prvrng.h`
file: simply call the `prvrng_test64p2()` function.

`prvrng_gen64p2()`-based generator passes [`PractRand`](http://pracrand.sourceforge.net/)
32 TB threshold. Which suggests it's the working universal TRNG.

Note that due to the structure of the core hash function the probability of
PRNG completely "stopping", or losing internal entropy, is absent.

This function, without external entropy injections, with any initial
combination of `lcg`, `Seed`, and `Hash` eventually converges into one of
random number sub-sequences. These are mostly time-delayed versions of only a
smaller set of unique sequences. There are structural limits in this PRNG
system which can be reached if there is only a small number of hash words in
the system. PRNG will continously produce non-repeating random sequences given
external entropy injections, but their statistical quality on a larger frames
will be limited by the size of `lcg` and `Seed` variables, the number of hash
words in the system, and the quality of the external entropy. A way to
increase the structural limit is to use a parallel PRNG structure demonstrated
in the `prvhash42s.h` file, which additionally increases the security
exponentially. Also any non-constant entropy input usually increases the
period of randomness, which, when extrapolated to hashing, means that the
period's exponent increases by message's entropy in bits, approximately.
The maximal PRNG period's `2^N` exponent approximately equals to full PRNG
system size in bits.

Moreover, the PRVHASH systems can be freely daisy-chained by feeding their
outputs to `lcg` inputs, adding guaranteed security firewalls, and increasing
the PRNG period of the final output accordingly.

While `lcg`, `Seed`, and `Hash` variables are best initialized with good
entropy source (however, structurally, they can accept just about any entropy
quality), the message can be sparsely-random: even an increasing counter can
be considered as having a suitable sparse entropy.

Since both internal variables (`Seed` and `lcg`) do not interact with the
output directly, the PRNG has a high level of security: it is not enough to
know the output of PRNG to predict its future values, or discover its prior
values.

If you have little confidence in OS-provided entropy (via `CryptGenRandom` or
`/dev/random/`), you may consider augmenting the `ctx -> lcg[ 0 ]` variable
yourself, before generating the required random number sequence. A good
independent source of entropy is user mouse event timing and positions: you
may simply apply something like `ctx -> lcg[ 0 ] ^= event_time_delta_micro;`
successively after generating at least 4 random bytes, or even combine the
mouse event time delta with mouse X-Y positions (via `XOR` or round-robin
manner). For best security, only the lower half of `lcg` should be augmented.
The best tactic is to augment `lcg` after generating a variable, not fixed,
number of random bytes, depending on mouse event time or position deltas: this
is efficient and allows one to disseminate sparse entropy represented by mouse
events over full system size.

## Streamed Hashing ##

The file `prvhash42s.h` implements a relatively fast streamed hashing
function by utilizing a parallel `prvhash42` structure. Please take a look
at the `prvhash42s_oneshot()` function for usage example. The `prvhash42s`
offers an extremely increased security and hashing speed. The amount of
entropy mixing going on in this implementation is substantial.

The default `prvhash42s.h`-based 64-bit hash of the string `The cat is out of
the bag` is `dc404b9669c712c2`.

The default `prvhash42s.h`-based 256-bit hash of the string
`Only a toilet bowl does not leak` is
`6fafde7561116d185f99fc70498a43192dcf2baed94047b1f27aa380f14fe025`.

The default prvhash42s 256-bit hash of the string
`Only a toilet bowl does not leal` is
`a537575d2796d691f42e968706d4cd112616f974e5efbef68e4ec8c920d322a5`.

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

## Description ##

Here is the author's vision on how the core hash function works. In actuality,
coming up with this solution was accompanied with a lot of trial and error.
It was especially hard to find a better "hashing finalization" solution.

	lcg ^= msgw; // Mix in message entropy into the system (for security, only lower half should be used).
	Seed += lcg; // Internal entropy mixing.
	Seed *= lcg - ~lcg; // Multiply random by random, assuring that no multiplication by zero takes place.
	lcg += ~Seed; // Internal entropy mixing.
	const uint64_t hs = Seed >> 32; // Obtain the higher part of Seed.
	const uint32_t out = (uint32_t) ( Seed ^ hs ); // Produce "compressed" output.
	uint32_t* const hc = (uint32_t*) &Hash[ hpos ]; // Take the address of the hash word.
	const uint64_t ph = *hc ^ hs; // Mix hash word with the internal entropy (truncated).
	Seed ^= ph; // Mix in the hash word. Entropy feedback.
	*hc = (uint32_t) ph; // Store the updated hash word.

(This core function can be arbitrarily scaled to any even-size variables:
2-, 4-, 8-, 16-, 32-, 64-bit variable sizes were tested, with similar
statistical results).

The first three instructions represent an "ideal" shuffler: it can be said
that for given the `lcg` and `Seed` values it remaps `msgw` uniquely.
Coupled with `lcg += ~Seed` and `Seed ^= Seed >> 32` instructions the whole
construction represents a "bivariable shuffler" which transforms `lcg` and
`Seed` variables into another pair of variables with asymptotically 50% bit
difference. The asymptota depends on the state variable size, is equal to
49.09% for 6-bit, 49.63% for 8-bit, 49.85% for 10-bit, 49.94% for 12-bit, etc
variables. Which means this system has a rather poor characteristics for 8-bit
state variables, but excellent characteristics for 64-bit variables.

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random sub-sequences. Hash
length affects the size of this "space of sub-sequences", permitting the
function to produce quality hashes for any required hash length.
Statistically, these "jumps" are very close to a purely random repositioning:
each new possible `lcg` value corresponds to a new random position, with a
spread over the whole PRNG period. The actual performace is a lot more
complicated as this PRNG system is able to converge into unrelated random
number sequences of varying lengths, so the "jump" changes both the position
and "index" of sequence. This property of PRVHASH assures that different
initial states of its `lcg` state variable produce practically unrelated
random number sequences, permitting to use PRVHASH for PRNG-based simulations.

How does it work? First of all, this PRNG system, represented by the core hash
function, does not work with numbers in a common sense: it works with [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)),
or random sequences of bits. The current "expression" of system's overall
internal entropy - the `Seed` - gets multiplied ("smeared") by a supportive
variable - `lcg`, - which is also a random value. Such multiplication changes
the `Seed` into a logarithmic-like distribution, dividing (in distribution
sense) its lower and higher parts. The `Seed` is then updated by a mix of its
own higher bits, `lcg`'s value, the hash word produced on previous rounds, and
the message. The reason the message's entropy (which may be sparse or
non-random) does not destabilize the system is because the message becomes
hidden in a mix of internal entropy; message's distribution becomes
irrelevant. The message "shifts" the system into a new state, predictated by
previous messages. Mixing the `Seed` with the hash word partly restores the
uniform distribution of `Seed`'s lower bits. Iterative mixing of the hash
words with the `Seed` assures that the resulting hashes follow uniform
distribution, irrespective of the distribution anomalies of the `Seed` itself.

In essence, the hash function generates a continuous pseudo-random number
sequence, and returns the final part of the sequence as a result. The message
acts as a "pathway" to this final part. So, the random sequence of numbers can
be "programmed" to produce a neccessary outcome. However, as this PRNG does
not expose its momentary internal state, such "programming" is hardly possible
to perform for an attacker, even if the entropy input channel is exposed:
consider an `A*(B+C)` equation, or more specifically, `(A+(B^C))*(B^C)`; an
adversary can control `C`, but does not know the values of `A` and `B`, thus
this adversary cannot predict the outcome.

P.S. The reason the InitVec in the `prvhash42` hash function have both value
constraints, and an initial state, is that otherwise the function would
require at least 4 "conditioning" preliminary rounds (core function calls), to
neutralize any oddities (including zero values) in InitVec; that would reduce
the performance of the hash function dramatically for table hash use. Note
that the `prvhash42s` function starts from the "full zero" state and then
performs acceptably.

## Method's Philosophy ##

Any external entropy (message) that enters this PRNG system acts as a
high-frequency and high-quality re-seeding which changes the random number
generator's "position" within the PRNG period, randomly. In practice, this
means that two messages that are different in even 1 bit produce "final"
random number sequences that are completely unrelated to each other. Since the
hash length affects the PRNG period of the system, the same logic applies to
hashes of any length, meeting collision and preimage resistance specifications
for all lengths.

## PRNG Period Assessment ##

The following "minimal" implementation for PractRand class can be used to
independently assess randomness period properties of PRVHASH. By varying
the `PH_HASH_COUNT` and `PH_PAR_COUNT` values it is possible to test various
PRNG system sizes. By adjusting other values it is possible to test PRVHASH
scalability across different state variable sizes. By additionally
uncommenting the `Ctr++` instruction it is possible to assess the PRNG period
increase due to sparse entropy input.

```
#include "prvhash42core.h"
#include <string.h>

#define PH_PAR_COUNT 1 // PRVHASH parallelism.
#define PH_HASH_COUNT 5 // Hash array word count.
#define PH_HASH_TYPE uint8_t // Hash word physical storage type.
#define PH_HASH_WORD_BITS 4 // Hash word size in bits.
#define PH_FN prvhash42_core8 // Core hash function name.
#define PH_STATE_TYPE uint8_t // State variable physical type.
#define PH_RAW_ROUNDS (32/PH_HASH_WORD_BITS) // PRVHASH rounds per 1 raw output.

class DummyRNG : public PractRand::RNGs::vRNG32 {
public:
    PH_STATE_TYPE Seed[ PH_PAR_COUNT ];
    PH_STATE_TYPE lcg[ PH_PAR_COUNT ];
    PH_HASH_TYPE Hash[ PH_HASH_COUNT ];
    int HashPos;
    PH_STATE_TYPE Ctr;

    DummyRNG() {
        memset( Seed, 0, sizeof( Seed ));
        memset( lcg, 0, sizeof( lcg ));
        memset( Hash, 0, sizeof( Hash ));
        HashPos = 0;
        Ctr = 0;
    }

    Uint32 raw32() {
        uint32_t OutValue = 0;
        int k, j;

        for( k = 0; k < PH_RAW_ROUNDS; k++ )
        {
//            Ctr++; Ctr &= 31; lcg[ 0 ] ^= Ctr;

            uint32_t h = 0;

            for( j = 0; j < PH_PAR_COUNT; j++ )
            {
                h ^= PH_FN( Seed + j, lcg + j, Hash + HashPos );
            }

            OutValue <<= PH_HASH_WORD_BITS;
            OutValue |= h;

            HashPos++;

            if( HashPos == PH_HASH_COUNT )
            {
                HashPos = 0;
            }
        }

        return( OutValue );
    }

    void walk_state(PractRand::StateWalkingObject *walker) {}
    void seed(Uint64 sv) { Seed[ 0 ] ^= sv; }
    std::string get_name() const { return "PRVHASH"; }
};
```

## PRVHASH Cryptanalysis Basics ##

As was noted previously, when the internal momentary state of PRVHASH is
known, its reversal poses a serious computational problem since the message
that enters the system becomes indistinguishable from system's own random
state. Moreover, each reversal round's complexity increases exponentially,
depending on the used PRVHASH parallelism (the `lcg - ~lcg` instruction
assures this: it naturally reduces bit size of `lcg` by 1 and thus induces
uncertainty about system's state).

When the system state is not known, when PRVHASH acts as a black-box, one has
to consider core hash function's statistical properties. Both halves of the
`Seed` and `lcg` variables, and the `Hash` value itself, are uniformly random:
they are uncorrelated to each other at all times, and are also wholly-unequal
during the PRNG period (they are not just time-delayed versions of each
other). When the message enters the system as `lcg ^= msgw`, it works like
mixing a message with an one-time-pad used in symmetric cryptography. This
operation completely hides the message in `lcg`'s entropy. Beside that the
output of PRVHASH uses "compression" operation over the `Seed` variable:
statistically, this means the mixing of two unrelated random variables. This
effectively hides the current state of the `Seed` variable, while a subsequent
mixing of the `Seed` with the `Hash` value invalidates the "compressed output"
value for use as a predictor of system's further state.

To sum up, the author is unable to find cryptographical security flaws in
PRVHASH. The author will be happy to offer a negotiable grant to any
cryptanalyst willing to "break" PRVHASH, or publish its cryptanalysis. You can
contact the author via aleksey.vaneev@gmail.com

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

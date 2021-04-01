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

PRVHASH can generate 64- to unlimited-bit hashes, yielding hashes of roughly
equal quality independent of the chosen hash length. PRVHASH is based on
64-bit math. The use of the function beyond 1024-bit hashes is easily
possible, but has to be statistically tested. For example, any 32-bit element
extracted from 2048-, or 4096-bit resulting hash is as collision resistant as
just a 32-bit hash. It is a fixed execution time hash function that depends
only on message length. A streamed hashing implementation is available.

PRVHASH is solely based on the butterfly effect, inspired by [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator)
pseudo-random number generators. The generated hashes have good avalanche
properties. For best results, when creating (H)MACs, a random seed should be
supplied to the hash function, but this is not a requirement. When each
message in a set is given a random seed, this allows hashes of such set to
have a greater statistical distance from each other. In practice, the
`InitVec` (instead of `SeedXOR`), and initial hash, can both be randomly
seeded (see the suggestions in `prvhash64.h`), adding useful initial entropy
(`InitVec` plus `Hash` total bits of entropy).

64-, 128-, 256-, 512- and 1024-bit PRVHASH hashes pass all [SMHasher](https://github.com/rurban/smhasher)
tests. Other hash lengths were not thoroughly tested, but extrapolations can
be made. PRVHASH possesses most of the cryptographic properties, but this
aspect has yet to be better proven.

In author's opinion, this hash function is provably [irreversible](https://en.wikipedia.org/wiki/One-way_function)
as it does not use fixed prime numbers, its output depends on all prior input,
the function has non-linearities (loss of state information) induced by bit
truncations, and because the message enters the system only as a mix with the
system's internal entropy without permutations of any sort. This reasoning
applies to the case when the internal state of the hashing system is known.
However, if the core hash function is a black-box, and only its output (`out`)
is known, it reveals no information about its prior or later state: all
elements of the core hash function (`Seed`, `lcg`, `out`, `Hash`) are
mutually-uncorrelated and wholly-unequal during the PRNG period. In this case,
the core hash function has the security level that is equal to its full bit
size (or message's size, if it is smaller).

Please see the `prvhash64.h` file for the details of the implementation (the
`prvhash.h`, `prvhash4.h`, `prvhash42.h` are outdated versions). Note that
`64` refers to core hash function's variable size.

The default `prvhash64.h`-based 64-bit hash of the string `The cat is out of
the bag` is `ecdcccb4f86e3569`.

A proposed short name for hashes created with `prvhash64.h` is `PRH64-N`,
where `N` is the hash length in bits (e.g. `PRH64-256`).

## PRVHASH64_64M ##

This is a minimized implementation of the `prvhash64` hash function. Since
arguably it's the smallest hash function in the world, that produces 64-bit
hashes of this quality level, it is very useful for hash tables.

## Entropy PRNG ##

PRVHASH can be also used as a very efficient general-purpose PRNG with an
external entropy source injections (like how the `/dev/urandom` works on
Unix): this was tested, and works well when 8-bit true entropy injections are
done inbetween 8 to 2048 generated random bytes (delay is also obtained via
the entropy source). An example generator is implemented in the `prvrng.h`
file: simply call the `prvrng_test64p2()` function.

`prvrng_gen64p2()`-based generator passes [`PractRand`](http://pracrand.sourceforge.net/)
32 TB threshold with rare non-systematic "unusual" evaluations. Which suggests
it's the working universal TRNG and randomness extractor that can "recycle"
entropy of any statistical quality, probably the first in the world.

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
words in the system, and the combinatorial capacity of the external entropy.
A way to increase the structural limit is to use a parallel PRNG structure
demonstrated in the `prvhash64s.h` file, which additionally increases the
security exponentially. Also any non-constant entropy input usually increases
the period of randomness, which, when extrapolated to hashing, means that the
period increases by message's combinatorial capacity (or the number of various
combinations of its bits). The maximal PRNG period's `2^N` exponent is hard to
approximate exactly, but in most tests it was equal to at least system's size
in bits, minus the number of hash words in the system, minus 1/4 of `lcg` and
`Seed` variables' size.

Moreover, the PRVHASH systems can be freely daisy-chained by feeding their
outputs to `Seed` inputs, adding guaranteed security firewalls, and increasing
the PRNG period of the final output accordingly. Note that any external PRNG
output should be inputted via `Seed`, not `lcg`, as to not be subject to
interference with the feedback path. For hashing, only input via `lcg` works
in practice.

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
successively after generating at least 8 random bytes, or even combine the
mouse event time delta with mouse X-Y positions (via `XOR` or round-robin
manner). The best tactic is to augment `lcg` after generating a variable, not
fixed, number of random bytes, depending on mouse event time or position
deltas: this is efficient and allows one to disseminate sparse entropy
represented by mouse events over full system size. Note that after
disseminating entropy, the PRNG should be first run in idle cycles to produce
`( PRVRNG_HASH_COUNT + 2 ) * 8` bytes of output to catch up on changes.

## Minimal PRNG for Everyday Use ##

The core hash function can be easily integrated into your applications, to be
used as an effective PRNG. The period of this minimal PRNG is at least
`2^160`. The initial parameters can be varied at will, and won't "break" the
PRNG. Setting only the `Seed` value guarantees a random start point within the
whole PRNG period, with at least `2^64` spacing. Here is the code:

```
#include "prvhash_core.h"
#include <stdio.h>

int main()
{
	uint64_t Seed = 0;
	uint64_t lcg = 0;
	uint64_t Hash = 0;

	uint64_t v = 0;
	uint64_t i;

	for( i = 0; i < ( 1ULL << 27 ); i++ )
	{
		v = prvhash_core64( &Seed, &lcg, &Hash );
	}

	printf( "%llu\n", v );
}
```

## Streamed Hashing ##

The file `prvhash64s.h` implements a relatively fast streamed hashing
function by utilizing a parallel `prvhash64` structure. Please take a look
at the `prvhash64s_oneshot()` function for usage example. The `prvhash64s`
offers an extremely increased security and hashing speed. The amount of
entropy mixing going on in this implementation is substantial.

The default `prvhash64s.h`-based 64-bit hash of the string `The cat is out of
the bag` is `a23b7ec63da0657d`.

The default `prvhash64s.h`-based 256-bit hash of the string
`Only a toilet bowl does not leak` is
`cb5dda3f9f4f8ebf714911bcb9ad1ed9b956fb593b411cb12d3a6776239d21ac`.

The default prvhash64s 256-bit hash of the string
`Only a toilet bowl does not leaj` is
`84c4a3cd346a361549bc806b63f6db3a0bfe79ef8b075641ee9397c485b4321a`.

This demonstrates the [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).
On a set of 216553 English words, pair-wise hash comparisons give average
50.0% difference in resulting hash bits, which fully satisfies the strict
avalanche criterion.

This streamed hash function produces hash values that are different to the
`prvhash64` hash function. It is incorrect to use both of these hash function
implementations on the same data set. While the `prvhash64` can be used as
a fast hash for tables, it is not so fast on large data blocks. The
`prvhash64s` can be used to create hashes of large data blocks like files.

A proposed short name for hashes created with `prvhash64s.h` is `PRH64S-N`,
where `N` is the hash length in bits (e.g. `PRH64S-256`).

## Description ##

Here is the author's vision on how the core hash function works. In actuality,
coming up with this solution was accompanied with a lot of trial and error.
It was especially hard to find a better "hashing finalization" solution.

	lcg ^= msgw; // Mix in external entropy (use `Seed` for daisy-chaining).
	const uint64_t plcg = lcg; // Save `lcg` for feedback.
	const uint64_t mx = Seed * ( lcg - ~lcg ); // Multiply random by random, without multiply by zero.
	const uint64_t rs = mx >> 32 | mx << 32; // Produce reversed copy (ideally, bit-reversed).
	lcg += ~mx; // Internal entropy mixing.
	Hash += rs; // Update hash word (summation produces uniform distribution).
	Seed = Hash ^ plcg; // Mix new reversed seed value with hash and previous `lcg`. Entropy feedback.
	const uint64_t out = lcg ^ rs; // Produce "compressed" output.

(This core function can be arbitrarily scaled to any even-size variables:
2-, 4-, 8-, 16-, 32-, 64-bit variable sizes were tested, with similar
statistical results).

How does it work? First of all, this PRNG system, represented by the core hash
function, does not work with numbers in a common sense: it works with [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)),
or random sequences of bits. The current "expression" of system's overall
internal entropy - the `Seed` - gets multiplied ("smeared") by a supportive
variable - `lcg`, - which is also a random value. Such multiplication produces
result with a logarithmic-like distribution. This result is then bit-reversed,
and is accumulated in the `Hash`. The `lcg` variable accumulates the result
with bit-inversion. The `Seed` is then updated with a mix of the bit-reversed
multiplication result, previous `lcg`'s value (that includes the message
input), and the hash word produced on previous rounds. The reason the
message's entropy (which may be sparse or non-random) does not destabilize the
system is because the message becomes hidden in a mix of internal entropy;
message's distribution becomes irrelevant. Both the accumulation of the
multiplication result and mixing of its bit-reversed and original version
produce a uniformly-distributed value.

The three instructions - `Seed ^= lcg`, `Seed *= lcg - ~lcg`, `lcg += ~Seed` -
represent an "ideal" bit shuffler: this construction represents a "bivariable
shuffler" which transforms input `lcg` and `Seed` variables into another pair
of variables with 50% bit difference relative to input, and no collisions. The
whole core hash function, however, uses a rearranged mixing, which produces a
hash value: the pair composed of the hash value and either a new `lcg` or a
new `Seed` value also produces no input-to-output collisions. Thus it can be
said that the system does not lose any input entropy. In 3-dimensional
analysis, when `Seed`, `lcg` and `msgw` values are scanned, and transformed
into output `Seed` and `Hash` value pairs, this system exhibits state
change-related collision statistics: on a fully random `msgw` input it is
adequate for 16-bit, and excellent for 64-bit variables (`5.47^-18` percent
chance, which far exceeds collision resistance requirements for 64-bit range
of bits). To further decrease state change collisions between `lcg` and `Seed`
with entropy input, the byte-reversal should be implemented as bit-reversal:
in this case the system reaches its optimal state, but this is
unimplementable in an efficient manner on modern processors. If the initial
state of the system has little or zero entropy (less than state variable size
bits of entropy), on very sparse `msgw` input (in the order of 1 bit per 80),
this system may initially exhibit local correlations between adjacent bits, so
in such case this system requires preliminary "conditioning" rounds (2 for
16-bit, and 5 for 64-bit state variables).

Another important aspect of this system, especially from the cryptography
standpoint, is entropy input to output latency. The base latency for
non-parallel state-to-state transition is equal to 1, and 2 for parallel;
and at the same time, 1 in hash-to-hash direction: this means that PRVHASH
additionally requires a full pass through the hash array for the entropy to
propagate. However, hashing also requires a pass to the end of the hash array
if message's length is shorter than the output hash, to "mix in" the initial
hash value. When there is only 1 hash word in use, for larger state variable
sizes there is practically no added delay, and thus the entropy propagation is
only subject to base latency. Empirically, however, entropy propagation speed
depends on the state variable size: for 8-bit variables 4 full hash array
passes are needed, for 16-bit variables 1 full pass is needed, but for 32-bit
variables no additional passes are needed in order to produce quality hashes.
Anyway, from the standpoint of the core hash function structure, 1 full pass
is needed to stay on a "safer" side.

Without external entropy (message) injections, the function can run for a
prolonged time, generating pseudo-entropy without much repetitions. When the
external entropy (message) is introduced, the function "shifts" into an
unrelated state unpredictably. So, it can be said that the function "jumps"
within a space of a huge number of pseudo-random sub-sequences. Hash
length affects the size of this "space of sub-sequences", permitting the
function to produce quality hashes for any required hash length.
Statistically, these "jumps" are close to a purely random repositioning:
each new possible `lcg` value corresponds to a new random position, with a
spread over the whole PRNG period. The actual performace is a lot more
complicated as this PRNG system is able to converge into unrelated random
number sequences of varying lengths, so the "jump" changes both the position
and "index" of sequence. This property of PRVHASH assures that different
initial states of its `lcg` state variable (or `Seed`, which is mostly
equivalent at initialization stage) produce practically unrelated random
number sequences, permitting to use PRVHASH for PRNG-based simulations.

In essence, the hash function generates a continuous pseudo-random number
sequence, and returns the final part of the sequence as a result. The message
acts as a "pathway" to this final part. So, the random sequence of numbers can
be "programmed" to produce a necessary outcome. However, as this PRNG does
not expose its momentary internal state, such "programming" is hardly possible
to perform for an attacker, even if the entropy input channel is exposed:
consider an `A*(B^C)` equation; an adversary can control `C`, but does not
know the values of `A` and `B`, thus this adversary cannot predict the
outcome. Beside that as the core hash function naturally eliminates the bias
from the external entropy of any statistical quality and frequency, its
control is fruitless. Since the function's output is "compressed", it gives no
hint on the internal state of the system.

P.S. The reason the InitVec in the `prvhash64` hash function has the value
constraints, and an initial state, is that otherwise the function would
require at least 5 "conditioning" preliminary rounds (core function calls), to
neutralize any oddities (including zero values) in InitVec; that would reduce
the performance of the hash function dramatically for table hash use. Note
that the `prvhash64s` function starts from the "full zero" state and then
performs acceptably.

## An Ideal Core Hash Function ##

The author found a variant of the core hash function that can be considered
"ideal" from PRNG/hashing point of view, as it features a minimal entropy
propagation latency. However, this variant turned out to be a lot slower, due
to reduced instruction parallelism.

	Seed ^= Hash ^ lcg;
	Seed *= lcg - ~lcg;
	lcg += ~Seed;
	rs = Seed >> 32 | Seed << 32;
	Hash += rs;
	out = lcg ^ rs;

You may wonder, what's the quality difference between this "ideal" function
and the "production" one, currently implemented in the `prvhash_core.h` file?
A short answer: there is no practical difference. The entropy propagation
latency depends on the structure of the function and the state variable size.
The "ideal" function having minimal latency gets a fast entropy propagation
even with 8-bit state variables. The current "production" function propagates
the entropy slower, and for 8-bit state variables requires more hash array
passes. However, if 16-bit state variables are used, there is no practical
difference between the "ideal" and "production" functions. This equality is
further strengthened when 64-bit state variables are used (larger state
variables have better shuffling statistics).

## Method's Philosophy ##

Any external entropy (message) that enters this PRNG system acts as a
high-frequency and high-quality re-seeding which changes the random number
generator's "position" within the PRNG period, randomly. In practice, this
means that two messages that are different in even 1 bit produce "final"
random number sequences, and thus hashes, that are completely unrelated to
each other. This also means that any smaller part of the resulting hash can be
used as a complete hash. Since the hash length affects the PRNG period (and
thus the combinatorial capacity) of the system, the same logic applies to
hashes of any length, while meeting collision and preimage resistance
specifications for all lengths.

Alternatively, the method can be viewed from the standpoint of classic
bit mixers/shufflers: the hash array can be seen as a "working buffer" whose
state is passed back into the "bivariable shuffler" continuously, and the new
shuffled values stored in such working buffer for later use.

## PRNG Period Assessment ##

The following "minimal" implementation for PractRand class can be used to
independently assess randomness period properties of PRVHASH. By varying
the `PH_HASH_COUNT` and `PH_PAR_COUNT` values it is possible to test various
PRNG system sizes. By adjusting other values it is possible to test PRVHASH
scalability across different state variable sizes (PractRand class and PRNG
output size should be matched, as PractRand test results depend on PRNG output
size). By additionally uncommenting the `Ctr++` instruction it is possible to
assess the PRNG period increase due to input of sparse entropy. The PractRand
should be run with the `-tlmin 64KB` parameter to evaluate changes to the
constants quicker. Note that both the `PH_HASH_COUNT` and `PH_PAR_COUNT`
affect the PRNG period exponent not exactly linearly for small variable sizes:
there is a saturation factor present for small variable sizes; after some
point the period increase is non-linear due to small shuffling space.
Shuffling space can be increased considerably with a parallel arrangement.
Depending on the initial seed value, the period may fluctuate.

```
#include "prvhash_core.h"
#include <string.h>

#define PH_PAR_COUNT 1 // PRVHASH parallelism.
#define PH_HASH_COUNT 4 // Hash array word count.
#define PH_STATE_TYPE uint8_t // State variable physical type.
#define PH_FN prvhash_core4 // Core hash function name.
#define PH_BITS 4 // State variable size in bits.
#define PH_RAW_BITS 8 // Raw output bits.
#define PH_RAW_ROUNDS ( PH_RAW_BITS / PH_BITS ) // Rounds per raw output.

class DummyRNG : public PractRand::RNGs::vRNG8 {
public:
    PH_STATE_TYPE Seed[ PH_PAR_COUNT ];
    PH_STATE_TYPE lcg[ PH_PAR_COUNT ];
    PH_STATE_TYPE Hash[ PH_HASH_COUNT ];
    int HashPos;
    PH_STATE_TYPE Ctr;

    DummyRNG() {
        memset( Seed, 0, sizeof( Seed ));
        memset( lcg, 0, sizeof( lcg ));
        memset( Hash, 0, sizeof( Hash ));
        HashPos = 0;
        Ctr = 0;
    }

    Uint8 raw8() {
        uint64_t OutValue = 0;
        int k, j;

        for( k = 0; k < PH_RAW_ROUNDS; k++ )
        {
//            Ctr++; lcg[ 0 ] ^= ( Ctr ^ ( Ctr >> 4 )) & 15;

            uint32_t h = 0;

            for( j = 0; j < PH_PAR_COUNT; j++ )
            {
                h = PH_FN( Seed + j, lcg + j, Hash + HashPos );
            }

            OutValue <<= PH_BITS;
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
to consider core hash function's statistical properties. All internal
variables - `Seed`, `lcg`, and `Hash` - are random: they are uncorrelated to
each other at all times, and are also wholly-unequal during the PRNG period
(they are not just time-delayed versions of each other). Moreover, as can be
assured with PractRand, all of these variables can be used as random number
generators: they can even be interleaved after each round.

When the message enters the system as `lcg ^= msgw`, it works like mixing a
message with an one-time-pad used in symmetric cryptography. This operation
completely hides the message in `lcg`'s entropy. Beside that the output of
PRVHASH uses mix of two variables: statistically, this means the mixing of two
unrelated random variables, with such summary output never appearing in
system's state. It's worth noting the `lcg ^ rs` expression: the `rs` variable
is composed of two halves, both of them practically being independent PRNG
outputs with period exponents smaller by half the state variable size. This
additionally complicates system's reversal.

To sum up, the author is unable to find cryptographical security flaws in
PRVHASH. The author will be happy to offer a negotiable grant to any
cryptanalyst willing to "break" PRVHASH, or publish its cryptanalysis. You can
contact the author via aleksey.vaneev@gmail.com . Note that it is possible to
perform "hard" computational experiments by using smaller state variable
sizes. This is what the author did extensively. However, a cryptanalysis also
requires mathematical analysis: it is there where any flaws can be found.

## PRVHASH16 ##

PRVHASH16 demonstrates the quality of the core hash function. While the state
variables are 16-bit, they are enough to perform hashing: this hash function
passes all SMHasher tests, like 64-bit PRVHASH function do, for any hash
length. This function is very slow, and is provided for demonstration purposes
only, to assure that the core hash function works in principle, independent of
state variable size. This hash function variant demonstrates that PRVHASH's
method does not rely on bit shuffling alone (shuffles are purely local), but
is genuinely based on PRNG position "jumps".

## Fused PRNG ##

While this "fused" arrangement is currently not used in the hash function
implementations, it is also working fine with the core hash function.
For example, while the "minimal PRNG" described above has 0.95 cycles/byte
performance, the "fused" arrangement has a PRNG performance of 0.41
cycles/byte, with a possibility of further scaling using AVX-512 instructions.

```
#include "prvhash_core.h"
#include <stdio.h>

int main()
{
	uint64_t Seed = 0;
	uint64_t lcg = 0;
	uint64_t Hash = 0;
	uint64_t Seed2 = 0;
	uint64_t lcg2 = 0;
	uint64_t Hash2 = 0;
	uint64_t Seed3 = 0;
	uint64_t lcg3 = 0;
	uint64_t Hash3 = 0;
	uint64_t Hash4 = 0;

	uint64_t v = 0;
	uint64_t v2 = 0;
	uint64_t v3 = 0;

	uint64_t i;

	for( i = 0; i < ( 1ULL << 27 ); i++ )
	{
		v = prvhash_core64( &Seed, &lcg, &Hash );
		v2 = prvhash_core64( &Seed2, &lcg2, &Hash2 );
		v3 = prvhash_core64( &Seed3, &lcg3, &Hash3 );

		uint64_t t = Hash;
		Hash = Hash2;
		Hash2 = Hash3;
		Hash3 = Hash4;
		Hash4 = t;
	}

	printf( "%llu %llu %llu\n", v, v2, v3 );
}
```

## Other ##

[Follow the author on Twitter](https://twitter.com/AlekseyVaneev)

[Become a patron on Patreon](https://patreon.com/aleksey_vaneev)

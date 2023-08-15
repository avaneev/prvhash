/**
 * prvhash_core.h version 4.3.2
 *
 * The inclusion file for the "prvhash_core*" PRVHASH core functions for
 * various state variable sizes. Also includes several auxiliary functions and
 * macros for endianness-correction.
 *
 * Description is available at https://github.com/avaneev/prvhash
 * E-mail: aleksey.vaneev@gmail.com or info@voxengo.com
 *
 * License
 *
 * Copyright (c) 2020-2023 Aleksey Vaneev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef PRVHASH_CORE_INCLUDED
#define PRVHASH_CORE_INCLUDED

#include <stdint.h>
#include <string.h>

#define PRVHASH_INIT_COUNT 5 // Common number of initialization rounds.

// Macro that denotes availability of required GCC-style built-in functions.

#if defined( __GNUC__ ) || defined( __clang__ ) || \
	defined( __IBMC__ ) || defined( __IBMCPP__ ) || defined( __COMPCERT__ )

	#define PRVHASH_GCC_BUILTINS

#endif // GCC built-ins.

// Macro to force code inlining.

#if defined( PRVHASH_GCC_BUILTINS )

	#define PRVHASH_INLINE inline __attribute__((always_inline))

#elif defined( _MSC_VER )

	#define PRVHASH_INLINE inline __forceinline

#else // defined( _MSC_VER )

	#define PRVHASH_INLINE inline

#endif // defined( _MSC_VER )

/**
 * This function runs a single PRVHASH random number generation round. This
 * function can be used both as a hash generator and as a general-purpose
 * random number generator. In either case, it is advisable to initially run
 * this function 5 times (independent of state variable's size), before using
 * its random output, to neutralize any possible oddities of state variables'
 * initial values (including zero values). Note that after such
 * initialization, any further "strange" or zero values in the hashword array
 * do not have any influence over the quality of the output (since they get
 * mixed with the Seed that already became uniformly-random).
 *
 * To generate hashes, the "Seed" and "lcg" variables should be simultaneously
 * XORed with the same entropy input, prior to calling this function.
 * Additionally, the "Seed" can be XORed with a good-quality uniformly-random
 * entropy (including output of another PRVHASH system): this is called
 * "daisy-chaining", it does not interfere with hashing.
 *
 * @param[in,out] Seed0 The current "Seed" value. Can be initialized to any
 * value.
 * @param[in,out] lcg0 The current "lcg" value. Can be initialized to any
 * value.
 * @param[in,out] Hash0 Current hash word in a hash word array.
 * @return Current random value.
 */

static PRVHASH_INLINE uint64_t prvhash_core64( uint64_t* const Seed0,
	uint64_t* const lcg0, uint64_t* const Hash0 )
{
	uint64_t Seed = *Seed0; uint64_t lcg = *lcg0; uint64_t Hash = *Hash0;

	Seed *= lcg * 2 + 1;
	const uint64_t rs = Seed >> 32 | Seed << 32;
	Hash += rs + 0xAAAAAAAAAAAAAAAA;
	lcg += Seed + 0x5555555555555555;
	Seed ^= Hash;
	const uint64_t out = lcg ^ rs;

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

static PRVHASH_INLINE uint32_t prvhash_core32( uint32_t* const Seed0,
	uint32_t* const lcg0, uint32_t* const Hash0 )
{
	uint32_t Seed = *Seed0; uint32_t lcg = *lcg0; uint32_t Hash = *Hash0;

	Seed *= lcg * 2 + 1;
	const uint32_t rs = Seed >> 16 | Seed << 16;
	Hash += rs + 0xAAAAAAAA;
	lcg += Seed + 0x55555555;
	Seed ^= Hash;
	const uint32_t out = lcg ^ rs;

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

static PRVHASH_INLINE uint16_t prvhash_core16( uint16_t* const Seed0,
	uint16_t* const lcg0, uint16_t* const Hash0 )
{
	uint16_t Seed = *Seed0; uint16_t lcg = *lcg0; uint16_t Hash = *Hash0;

	Seed *= (uint16_t) ( lcg * 2 + 1 );
	const uint16_t rs = (uint16_t) ( Seed >> 8 | Seed << 8 );
	Hash += (uint16_t) ( rs + 0xAAAA );
	lcg += (uint16_t) ( Seed + 0x5555 );
	Seed ^= Hash;
	const uint16_t out = (uint16_t) ( lcg ^ rs );

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

static PRVHASH_INLINE uint8_t prvhash_core8( uint8_t* const Seed0,
	uint8_t* const lcg0, uint8_t* const Hash0 )
{
	uint8_t Seed = *Seed0; uint8_t lcg = *lcg0; uint8_t Hash = *Hash0;

	Seed *= (uint8_t) ( lcg * 2 + 1 );
	const uint8_t rs = (uint8_t) ( Seed >> 4 | Seed << 4 );
	Hash += (uint8_t) ( rs + 0xAA );
	lcg += (uint8_t) ( Seed + 0x55 );
	Seed ^= Hash;
	const uint8_t out = (uint8_t) ( lcg ^ rs );

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

static PRVHASH_INLINE uint8_t prvhash_core4( uint8_t* const Seed0,
	uint8_t* const lcg0, uint8_t* const Hash0 )
{
	uint8_t Seed = *Seed0; uint8_t lcg = *lcg0; uint8_t Hash = *Hash0;

	Seed *= (uint8_t) ( lcg * 2 + 1 );
	Seed &= 15;
	const uint8_t rs = (uint8_t) (( Seed >> 2 | Seed << 2 ) & 15 );
	Hash += (uint8_t) ( rs + 0xA );
	Hash &= 15;
	lcg += (uint8_t) ( Seed + 0x5 );
	lcg &= 15;
	Seed ^= Hash;
	const uint8_t out = (uint8_t) ( lcg ^ rs );

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

static PRVHASH_INLINE uint8_t prvhash_core2( uint8_t* const Seed0,
	uint8_t* const lcg0, uint8_t* const Hash0 )
{
	uint8_t Seed = *Seed0; uint8_t lcg = *lcg0; uint8_t Hash = *Hash0;

	Seed *= (uint8_t) ( lcg * 2 + 1 );
	Seed &= 3;
	const uint8_t rs = (uint8_t) (( Seed >> 1 | Seed << 1 ) & 3 );
	Hash += (uint8_t) ( rs + 0x2 );
	Hash &= 3;
	lcg += (uint8_t) ( Seed + 0x1 );
	lcg &= 3;
	Seed ^= Hash;
	const uint8_t out = (uint8_t) ( lcg ^ rs );

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

#if defined( __SIZEOF_INT128__ )

static PRVHASH_INLINE unsigned __int128 prvhash_core128(
	unsigned __int128* const Seed0, unsigned __int128* const lcg0,
	unsigned __int128* const Hash0 )
{
	unsigned __int128 Seed = *Seed0; unsigned __int128 lcg = *lcg0;
	unsigned __int128 Hash = *Hash0;

	Seed *= lcg * 2 + 1;
	const unsigned __int128 rs = Seed >> 64 | Seed << 64;
	Hash += rs +
		( 0xAAAAAAAAAAAAAAAA | (unsigned __int128) 0xAAAAAAAAAAAAAAAA << 64 );

	lcg += Seed +
		( 0x5555555555555555 | (unsigned __int128) 0x5555555555555555 << 64 );

	Seed ^= Hash;
	const unsigned __int128 out = lcg ^ rs;

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

#endif // defined( __SIZEOF_INT128__ )

// Endianness definition macro, can be used as a logical constant.

#if defined( __LITTLE_ENDIAN__ ) || defined( __LITTLE_ENDIAN ) || \
	defined( _LITTLE_ENDIAN ) || defined( _WIN32 ) || defined( i386 ) || \
	defined( __i386 ) || defined( __i386__ ) || defined( __x86_64__ ) || \
	( defined( __BYTE_ORDER__ ) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )

	#define PRVHASH_LITTLE_ENDIAN 1

#elif defined( __BIG_ENDIAN__ ) || defined( __BIG_ENDIAN ) || \
	defined( _BIG_ENDIAN ) || defined( __SYSC_ZARCH__ ) || \
	defined( __zarch__ ) || defined( __s390x__ ) || defined( __sparc ) || \
	defined( __sparc__ ) || \
	( defined( __BYTE_ORDER__ ) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )

	#define PRVHASH_LITTLE_ENDIAN 0

#else // defined( __BIG_ENDIAN__ )

	#warning PRVHASH: cannot determine endianness, assuming little-endian.

	#define PRVHASH_LITTLE_ENDIAN 1

#endif // defined( __BIG_ENDIAN__ )

// Macros that apply byte-swapping, used for endianness-correction.

#if PRVHASH_LITTLE_ENDIAN

	#define PRVHASH_EC32( v ) ( v )
	#define PRVHASH_EC64( v ) ( v )

#else // PRVHASH_LITTLE_ENDIAN

	#if defined( PRVHASH_GCC_BUILTINS )

		#define PRVHASH_EC32( v ) __builtin_bswap32( v )
		#define PRVHASH_EC64( v ) __builtin_bswap64( v )

	#elif defined( _MSC_VER )

		#include <intrin.h>

		#define PRVHASH_EC32( v ) _byteswap_ulong( v )
		#define PRVHASH_EC64( v ) _byteswap_uint64( v )

	#else // defined( _MSC_VER )

		#define PRVHASH_EC32( v ) ( \
			( v & 0xFF000000 ) >> 24 | \
			( v & 0x00FF0000 ) >> 8 | \
			( v & 0x0000FF00 ) << 8 | \
			( v & 0x000000FF ) << 24 )

		#define PRVHASH_EC64( v ) ( \
			( v & 0xFF00000000000000 ) >> 56 | \
			( v & 0x00FF000000000000 ) >> 40 | \
			( v & 0x0000FF0000000000 ) >> 24 | \
			( v & 0x000000FF00000000 ) >> 8 | \
			( v & 0x00000000FF000000 ) << 8 | \
			( v & 0x0000000000FF0000 ) << 24 | \
			( v & 0x000000000000FF00 ) << 40 | \
			( v & 0x00000000000000FF ) << 56 )

	#endif // defined( _MSC_VER )

#endif // PRVHASH_LITTLE_ENDIAN

/**
 * An auxiliary function that returns an unsigned 32-bit value created out of
 * individual bytes in a buffer. This function is used to convert endianness
 * of supplied 32-bit unsigned values, and to avoid unaligned memory accesses.
 *
 * @param p 4-byte buffer. Alignment is unimportant.
 */

static PRVHASH_INLINE uint32_t prvhash_lu32ec( const uint8_t* const p )
{
	uint32_t v;
	memcpy( &v, p, 4 );

	return( PRVHASH_EC32( v ));
}

/**
 * An auxiliary function that returns an unsigned 64-bit value created out of
 * individual bytes in a buffer. This function is used to convert endianness
 * of supplied 64-bit unsigned values, and to avoid unaligned memory accesses.
 *
 * @param p 8-byte buffer. Alignment is unimportant.
 */

static PRVHASH_INLINE uint64_t prvhash_lu64ec( const uint8_t* const p )
{
	uint64_t v;
	memcpy( &v, p, 8 );

	return( PRVHASH_EC64( v ));
}

#endif // PRVHASH_CORE_INCLUDED

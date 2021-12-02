/**
 * prvhash64.h version 4.2
 *
 * The inclusion file for the "prvhash64" and "prvhash64_64m" hash functions.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020-2021 Aleksey Vaneev
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

#ifndef PRVHASH64_INCLUDED
#define PRVHASH64_INCLUDED

#include "prvhash_core.h"

#define PRH64_T uint64_t // PRVHASH state variable type.
#define PRH64_S sizeof( PRH64_T ) // State variable type's size.
#define PRH64_Sm1 ( PRH64_S - 1 ) // = PRH64_S - 1.
#define PRH64_FN prvhash_core64 // PRVHASH function name.
#define PRH64_LUEC( v ) prvhash_lu64ec( v ) // Value load function, with EC.
#define PRH64_LPUEC prvhash_lpu64ec // Value load function, pad, EC.
#define PRH64_EC( v ) PRVHASH_EC64( v ) // Value endianness-correction.

/**
 * PRVHASH hash function (64-bit variables). Produces hash of the specified
 * message. This function applies endianness correction to the resulting hash
 * automatically (on little- and big-endian processors).
 *
 * @param Msg0 The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[in,out] Hash0 The resulting hash. The length of this buffer should
 * be equal to HashLen. If InitVec is non-NULL, the hash will not be initially
 * reset to 0, and it should be pre-initialized with uniformly-random bytes
 * (there are no restrictions on which values to use for initialization: even
 * an all-zero value can be used). The provided hash will be automatically
 * endianness-corrected. On systems where this is relevant, this address
 * should be aligned to PRH64_S bytes.
 * @param HashLen The required hash length, in bytes, should be >= PRH64_S,
 * in increments of PRH64_S.
 * @param UseSeed Optional value, to use instead of the default seed. To use
 * the default seed, set to 0. If InitVec is non-NULL, this UseSeed is ignored
 * and should be set to 0. Otherwise, the UseSeed value can have any bit
 * length and statistical quality, and is used only as an additional entropy
 * source. If this value is shared between big- and little-endian systems,
 * it should be endianness-corrected.
 * @param InitVec0 If non-NULL, an "initialization vector" for internal "Seed"
 * and "lcg" variables. Full 16-byte uniformly-random value should be supplied
 * in this case. Since it is imperative that the initialization vector is
 * non-zero and non-sparse, the best strategies to generate it are: 1) compose
 * the vector from 16-bit random values that have 4 to 12 random bits set;
 * 2) compose the vector from 64-bit random values that have 28-36 random bits
 * set. The provided values will be automatically endianness-corrected. This
 * vector's address alignment is unimportant.
 */

static inline void prvhash64( const void* const Msg0, const size_t MsgLen,
	void* const Hash0, const size_t HashLen, const PRH64_T UseSeed,
	const void* const InitVec0 )
{
	const uint8_t* Msg = (const uint8_t*) Msg0;
	uint8_t* const Hash = (uint8_t*) Hash0;
	const uint8_t* const InitVec = (const uint8_t*) InitVec0;

	PRH64_T Seed;
	PRH64_T lcg;

	if( PRVHASH_LIKELY( InitVec == 0 ))
	{
		memset( Hash, 0, HashLen );

		Seed = 0x243F6A8885A308D3; // The first mantissa bits of PI.
		lcg = 0x13198A2E03707344;
		*(PRH64_T*) Hash = UseSeed;
	}
	else
	{
		size_t k;

		for( k = 0; PRVHASH_LIKELY( k < HashLen ); k += PRH64_S )
		{
			*(PRH64_T*) ( Hash + k ) = PRH64_LUEC( Hash + k );
		}

		Seed = PRH64_LUEC( InitVec );
		lcg = PRH64_LUEC( InitVec + PRH64_S );
	}

	const uint8_t* const MsgEnd = Msg + MsgLen;
	const PRH64_T* const HashEnd = (PRH64_T*) ( Hash + HashLen );
	PRH64_T* hc = (PRH64_T*) Hash;

	PRH64_T fb = 1;

	if( PRVHASH_LIKELY( MsgLen != 0 ))
	{
		fb <<= ( MsgEnd[ -1 ] >> 7 );
	}

	while( 1 )
	{
		if( PRVHASH_LIKELY( Msg < MsgEnd - PRH64_Sm1 ))
		{
			const PRH64_T msgw = PRH64_LUEC( Msg );

			Seed ^= msgw;
			lcg ^= msgw;
		}
		else
		{
			if( PRVHASH_UNLIKELY( Msg > MsgEnd ))
			{
				break;
			}

			const PRH64_T msgw = PRH64_LPUEC( Msg, MsgEnd, fb );

			Seed ^= msgw;
			lcg ^= msgw;
		}

		PRH64_FN( &Seed, &lcg, hc );

		if( PRVHASH_UNLIKELY( ++hc == HashEnd ))
		{
			hc = (PRH64_T*) Hash;
		}

		Msg += PRH64_S;
	}

	const size_t fc = ( HashLen == PRH64_S ? 0 : HashLen +
		( MsgLen < HashLen - PRH64_S ?
		(uint8_t*) HashEnd - (uint8_t*) hc : 0 ));

	size_t k;

	for( k = 0; PRVHASH_LIKELY( k <= fc ); k += PRH64_S )
	{
		PRH64_FN( &Seed, &lcg, hc );

		if( PRVHASH_UNLIKELY( ++hc == HashEnd ))
		{
			hc = (PRH64_T*) Hash;
		}
	}

	for( k = 0; PRVHASH_LIKELY( k < HashLen ); k += PRH64_S )
	{
		*hc = PRH64_EC( PRH64_FN( &Seed, &lcg, hc ));

		if( PRVHASH_UNLIKELY( ++hc == HashEnd ))
		{
			hc = (PRH64_T*) Hash;
		}
	}
}

/**
 * PRVHASH hash function. Produces and returns 64-bit hash of the specified
 * message. This is a "minimal" implementation. Designed for 64-bit table hash
 * use. Equivalent to "prvhash64" function with HashLen == 8, but returns an
 * immediate result (endianness-correction is not required).
 *
 * @param Msg0 The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param UseSeed Optional value, to use instead of the default seed. To use
 * the default seed, set to 0. The UseSeed value can have any bit length and
 * statistical quality, and is used only as an additional entropy source. If
 * this value is shared between big- and little-endian systems, it should be
 * endianness-corrected.
 */

static inline uint64_t prvhash64_64m( const void* const Msg0,
	const size_t MsgLen, const PRH64_T UseSeed )
{
	const uint8_t* Msg = (const uint8_t*) Msg0;

	PRH64_T Seed = 0x243F6A8885A308D3; // The first mantissa bits of PI.
	PRH64_T lcg = 0x13198A2E03707344;
	PRH64_T Hash = UseSeed;

	const uint8_t* const MsgEnd = Msg + MsgLen;

	PRH64_T fb = 1;

	if( PRVHASH_LIKELY( MsgLen != 0 ))
	{
		fb <<= ( MsgEnd[ -1 ] >> 7 );
	}

	while( 1 )
	{
		if( PRVHASH_LIKELY( Msg < MsgEnd - PRH64_Sm1 ))
		{
			const PRH64_T msgw = PRH64_LUEC( Msg );

			Seed ^= msgw;
			lcg ^= msgw;
		}
		else
		{
			if( PRVHASH_UNLIKELY( Msg > MsgEnd ))
			{
				PRH64_FN( &Seed, &lcg, &Hash );

				return( PRH64_FN( &Seed, &lcg, &Hash ));
			}

			const PRH64_T msgw = PRH64_LPUEC( Msg, MsgEnd, fb );

			Seed ^= msgw;
			lcg ^= msgw;
		}

		PRH64_FN( &Seed, &lcg, &Hash );

		Msg += PRH64_S;
	}
}

#endif // PRVHASH64_INCLUDED

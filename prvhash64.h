/**
 * prvhash64.h version 3.3
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
#include "prvhash_aux.h"

/**
 * PRVHASH hash function (64-bit variables). Produces hash of the specified
 * message. This function applies endianness correction to the resulting hash
 * automatically (on little- and big-endian processors).
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[in,out] Hash The resulting hash. The length of this buffer should be
 * equal to HashLen. If InitVec is non-NULL, the hash will not be initially
 * reset to 0, and it should be pre-initialized with uniformly-random bytes
 * (there are no restrictions on which values to use for initialization: even
 * an all-zero value can be used). The provided hash will be automatically
 * endianness-corrected. On systems where this is relevant, this address
 * should be aligned to 64 bits.
 * @param HashLen The required hash length, in bytes, should be >= 8, in
 * increments of 8.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. If InitVec is non-NULL, this SeedXOR is ignored and
 * should be set to 0. Otherwise, the SeedXOR value can have any bit length,
 * and is used only as an additional entropy source. It should be
 * endianness-corrected.
 * @param InitVec If non-NULL, an "initialization vector" for internal "Seed"
 * and "lcg" variables. Full 16-byte uniformly-random value should be supplied
 * in this case. Since it is imperative that the initialization vector is
 * non-zero, the best strategies to generate it are: 1) compose the vector
 * from 16-bit random values that have 4 to 12 random bits set; 2) compose the
 * vector from 64-bit random values that have 28-36 random bits set.
 */

inline void prvhash64( const uint8_t* Msg, const size_t MsgLen,
	uint8_t* const Hash, const size_t HashLen, const uint64_t SeedXOR,
	const uint8_t InitVec[ 16 ])
{
	typedef uint64_t state_t;

	state_t Seed;
	state_t lcg;

	if( InitVec == 0 )
	{
		memset( Hash, 0, HashLen );

		Seed = 12905183526369792234ULL;
		lcg = 0;
		*(state_t*) Hash = SeedXOR;
	}
	else
	{
		prvhash_ec64( Hash, HashLen );

		Seed = prvhash_lu64ec( InitVec );
		lcg = prvhash_lu64ec( InitVec + 8 );
	}

	const uint8_t* const MsgEnd = Msg + MsgLen;
	const state_t* const HashEnd = (state_t*) ( Hash + HashLen );
	state_t* hc = (state_t*) Hash;

	state_t fb = 1;

	if( MsgLen > 0 )
	{
		fb <<= ( Msg[ MsgLen - 1 ] >> 7 );
	}

	while( 1 )
	{
		if( Msg < MsgEnd - 7 )
		{
			lcg ^= prvhash_lu64ec( Msg );
		}
		else
		{
			if( Msg > MsgEnd )
			{
				break;
			}

			lcg ^= prvhash_lpu64_f( Msg, MsgEnd, fb );
		}

		prvhash_core64( &Seed, &lcg, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (state_t*) Hash;
		}

		Msg += sizeof( state_t );
	}

	const size_t fc = ( HashLen == sizeof( state_t ) ? 0 : HashLen +
		( MsgLen < HashLen - sizeof( state_t ) ?
		(uint8_t*) HashEnd - (uint8_t*) hc : 0 ));

	size_t k;

	for( k = 0; k <= fc; k += sizeof( state_t ))
	{
		prvhash_core64( &Seed, &lcg, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (state_t*) Hash;
		}
	}

	for( k = 0; k < HashLen; k += sizeof( state_t ))
	{
		*hc = prvhash_core64( &Seed, &lcg, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (state_t*) Hash;
		}
	}

	prvhash_ec64( Hash, HashLen );
}

/**
 * PRVHASH hash function. Produces and returns 64-bit hash of the specified
 * message. This is a "minimal" implementation. Designed for 64-bit table hash
 * use. Equivalent to "prvhash64" function with HashLen == 8, but returns an
 * immediate result (endianness-correction is not required).
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. The SeedXOR value can have any bit length, and is
 * used only as an additional entropy source.
 */

inline uint64_t prvhash64_64m( const uint8_t* Msg, const size_t MsgLen,
	const uint64_t SeedXOR )
{
	typedef uint64_t state_t;

	state_t Seed = 12905183526369792234ULL;
	state_t lcg = 0;
	state_t HashVal = SeedXOR;

	state_t fb = 1;

	if( MsgLen > 0 )
	{
		fb <<= ( Msg[ MsgLen - 1 ] >> 7 );
	}

	const uint8_t* const MsgEnd = Msg + MsgLen;

	while( 1 )
	{
		if( Msg < MsgEnd - 7 )
		{
			lcg ^= prvhash_lu64ec( Msg );
		}
		else
		{
			if( Msg > MsgEnd )
			{
				prvhash_core64( &Seed, &lcg, &HashVal );

				return( prvhash_core64( &Seed, &lcg, &HashVal ));
			}

			lcg ^= prvhash_lpu64_f( Msg, MsgEnd, fb );
		}

		prvhash_core64( &Seed, &lcg, &HashVal );

		Msg += sizeof( state_t );
	}
}

#endif // PRVHASH64_INCLUDED

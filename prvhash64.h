/**
 * prvhash64.h version 4.3.4
 *
 * The inclusion file for the "prvhash64" and "prvhash64_64m" hash functions.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020-2025 Aleksey Vaneev
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
 * Function loads 64-bit message word and pads it with the "final byte". This
 * function should only be called if there are less than 8 bytes left to read.
 * Function performs endianness-correction automatically.
 *
 * @param Msg Message pointer, alignment is unimportant. Should be below or
 * equal to MsgEnd.
 * @param MsgEnd Message's end pointer.
 * @param fb Final byte used for padding.
 */

static PRVHASH_INLINE uint64_t prvhash_lpu64ec( const uint8_t* const Msg,
	const uint8_t* const MsgEnd, uint64_t fb )
{
	const size_t MsgLen = MsgEnd - Msg;
	const int ml8 = (int) ( MsgLen << 3 );

	if( MsgLen < 4 )
	{
		if( MsgLen != 0 )
		{
			fb = fb << ml8 | Msg[ 0 ];

			if( MsgLen > 1 )
			{
				fb |= (uint64_t) Msg[ 1 ] << 8;

				if( MsgLen > 2 )
				{
					fb |= (uint64_t) Msg[ 2 ] << 16;
				}
			}
		}

		return( fb );
	}

	const uint64_t mh = prvhash_lu32ec( MsgEnd - 4 );
	const uint64_t ml = prvhash_lu32ec( Msg );

	return( fb << ml8 | ml | ( mh >> ( 64 - ml8 )) << 32 );
}

/**
 * PRVHASH hash function (64-bit variables). Produces a hash of the specified
 * message, string, or binary data block. This function applies
 * endianness-correction to the resulting hash automatically (on little- and
 * big-endian processors).
 *
 * @param Msg0 The message to produce a hash from. The alignment of this
 * pointer is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[out] HashOut The resulting hash. The length of this buffer should
 * be equal to HashLen. On systems where this is relevant, this address should
 * be aligned to PRH64_S bytes.
 * @param HashLen The required hash length, in bytes; should be >= PRH64_S,
 * in increments of PRH64_S; no higher-value limits.
 * @param UseSeed Optional value, to use instead of the default seed. To use
 * the default seed, set to 0. The UseSeed value can have any bit length and
 * statistical quality, and is used only as an additional entropy source. If
 * this value is shared between big- and little-endian systems, it should be
 * endianness-corrected.
 */

static inline void prvhash64( const void* const Msg0, const size_t MsgLen,
	void* const HashOut, const size_t HashLen, const PRH64_T UseSeed )
{
	const uint8_t* Msg = (const uint8_t*) Msg0;
	PRH64_T* const Hash = (PRH64_T*) HashOut;

	memset( Hash, 0, HashLen );

	// The state after 5 prvhash_core64() rounds from the "zero-state".

	PRH64_T Seed = 0x217992B44669F46A ^ UseSeed;
	PRH64_T lcg = 0xB5E2CC2FE9F0B35B ^ UseSeed;
	Hash[ 0 ] = 0x949B5E0A608D76D5;

	const uint8_t* const MsgEnd = Msg + MsgLen;
	const PRH64_T* const HashEnd = Hash + HashLen / PRH64_S;
	PRH64_T* hc = Hash;

	while( 1 )
	{
		PRH64_FN( &Seed, &lcg, hc );
		hc = ( ++hc == HashEnd ? Hash : hc );

		PRH64_T msgw;

		if( Msg < MsgEnd - PRH64_Sm1 )
		{
			msgw = PRH64_LUEC( Msg );
		}
		else
		{
			if( Msg > MsgEnd )
			{
				break;
			}

			msgw = PRH64_LPUEC( Msg, MsgEnd, 0x10 );
		}

		Seed ^= msgw;
		lcg ^= msgw;

		Msg += PRH64_S;
	}

	const size_t fc = ( HashLen == PRH64_S ? 0 :
		HashLen + ( MsgLen + PRH64_S * 2 < HashLen ?
		(uint8_t*) HashEnd - (uint8_t*) hc : 0 ));

	size_t k;

	for( k = 0; k <= fc; k += PRH64_S )
	{
		PRH64_FN( &Seed, &lcg, hc );
		hc = ( ++hc == HashEnd ? Hash : hc );
	}

	for( k = 0; k < HashLen; k += PRH64_S )
	{
		*hc = PRH64_EC( PRH64_FN( &Seed, &lcg, hc ));
		hc = ( ++hc == HashEnd ? Hash : hc );
	}
}

/**
 * PRVHASH hash function. Produces and returns a 64-bit hash of the specified
 * message, string, or binary data block. This is a "minimal" implementation,
 * designed for 64-bit hash-table and hash-map uses. Equivalent to the
 * "prvhash64" function with HashLen == 8, but returns an immediate result
 * (endianness-correction is not required).
 *
 * @param Msg0 The message to produce a hash from. The alignment of this
 * pointer is unimportant.
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

	// The state after 5 prvhash_core64() rounds from the "zero-state".

	PRH64_T Seed = 0x217992B44669F46A ^ UseSeed;
	PRH64_T lcg = 0xB5E2CC2FE9F0B35B ^ UseSeed;
	PRH64_T Hash = 0x949B5E0A608D76D5;

	const uint8_t* const MsgEnd = Msg + MsgLen;

	while( 1 )
	{
		PRH64_FN( &Seed, &lcg, &Hash );

		PRH64_T msgw;

		if( Msg < MsgEnd - PRH64_Sm1 )
		{
			msgw = PRH64_LUEC( Msg );
		}
		else
		{
			if( Msg > MsgEnd )
			{
				PRH64_FN( &Seed, &lcg, &Hash );

				return( PRH64_FN( &Seed, &lcg, &Hash ));
			}

			msgw = PRH64_LPUEC( Msg, MsgEnd, 0x10 );
		}

		Seed ^= msgw;
		lcg ^= msgw;

		Msg += PRH64_S;
	}
}

#endif // PRVHASH64_INCLUDED

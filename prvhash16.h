/**
 * prvhash16.h version 3.0
 *
 * The inclusion file for the "prvhash16" hash function.
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

#ifndef PRVHASH16_INCLUDED
#define PRVHASH16_INCLUDED

#include "prvhash_core.h"
#include "prvhash_aux.h"

/**
 * PRVHASH hash function (16-bit variables). Produces hash of the specified
 * message. This function does not apply endianness correction to the
 * resulting hash.
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[in,out] Hash The resulting hash. The length of this buffer should be
 * equal to HashLen. On systems where this is relevant, this address should be
 * aligned to 16 bits.
 * @param HashLen The required hash length, in bytes, should be >= 4, in
 * increments of 2.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. The SeedXOR value can have any bit length,
 * and is used only as an additional entropy source.
 */

inline void prvhash16( const uint8_t* Msg, const size_t MsgLen,
	uint8_t* const Hash, const size_t HashLen, const uint32_t SeedXOR )
{
	memset( Hash, 0, HashLen );

	typedef uint16_t state_t;
	state_t Seed = 48976;
	state_t lcg = 0;
	*(uint32_t*) Hash = 1290518352UL ^ SeedXOR;

	Seed ^= (state_t) ( HashLen >> 1 );

	const state_t* const HashEnd = (state_t*) ( Hash + HashLen );
	state_t* hc = (state_t*) Hash;
	state_t fbm = 0;

	if( MsgLen > 0 )
	{
		fbm -= ( ~Msg[ MsgLen - 1 ] >> 7 ) & 1;

		const uint8_t fb = (uint8_t) fbm;
		const uint8_t* const MsgEnd = Msg + MsgLen;

		while( Msg < MsgEnd )
		{
			lcg ^= (state_t) ( *Msg |
				(state_t) ( Msg + 1 < MsgEnd ? *( Msg + 1 ) : fb ) << 8 );

			prvhash_core16( &Seed, &lcg, hc );

			hc++;

			if( hc == HashEnd )
			{
				hc = (state_t*) Hash;
			}

			Msg += sizeof( state_t );
		}
	}

	size_t k;

	for( k = 0; k <= HashLen; k += sizeof( state_t ))
	{
		lcg ^= fbm;
		prvhash_core16( &Seed, &lcg, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (state_t*) Hash;
		}
	}

	for( k = 0; k < HashLen; k += sizeof( state_t ))
	{
		lcg ^= fbm;
		*hc = prvhash_core16( &Seed, &lcg, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (state_t*) Hash;
		}
	}
}

#endif // PRVHASH16_INCLUDED

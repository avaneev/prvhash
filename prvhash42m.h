/**
 * prvhash42m.h version 2.31
 *
 * The inclusion file for the "prvhash42m_32" hash function, specially
 * designed for table hash use (due to small size).
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020 Aleksey Vaneev
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

#ifndef PRVHASH42M_INCLUDED
#define PRVHASH42M_INCLUDED

#include "prvhash42core.h"
#include "prvhash42ec.h"

/**
 * PRVHASH hash function (64-bit variables with 32-bit hash word). Produces
 * and returns 32-bit hash of the specified message. This is a "minimal"
 * implementation that uses PRVHASH's property of PRNG period extension due to
 * entropy input. Designed for 32-bit table hash use.
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. The SeedXOR value can have any bit length, and is
 * used only as an additional entropy source.
 */

inline uint32_t prvhash42m_32( const uint8_t* Msg, const int MsgLen,
	const uint64_t SeedXOR )
{
	uint64_t Seed = 12905183526369792234ULL ^ SeedXOR;
	uint64_t lcg = 6447574768757703757ULL;
	uint32_t HashVal = 0;

	uint64_t fbm = 0;

	if( MsgLen > 0 )
	{
		fbm -= (uint64_t) (( ~Msg[ MsgLen - 1 ] >> 7 ) & 1 );
	}

	const uint8_t fb = (uint8_t) fbm;
	const uint8_t* const MsgEnd = Msg + MsgLen;
	int sc = 1 + (( MsgLen & 7 ) == 0 );

	while( 1 )
	{
		if( Msg < MsgEnd )
		{
			lcg ^= prvhash42_lp64_1( Msg, MsgEnd, fb );
			Msg += 8;
		}
		else
		{
			lcg ^= fbm;
			sc--;
		}

		const uint32_t h = prvhash42_core64( &Seed, &lcg, &HashVal );

		if( sc < 0 )
		{
			return( h );
		}
	}
}

#endif // PRVHASH42M_INCLUDED

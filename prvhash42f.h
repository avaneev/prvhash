/**
 * prvhash42f.h version 2.31
 *
 * The inclusion file for the "prvhash42f" hash function, specially
 * designed for competitive performance.
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

#ifndef PRVHASH42F_INCLUDED
#define PRVHASH42F_INCLUDED

#include "prvhash42ec.h"

/**
 * "Modified" "fast" PRVHASH hash function (64-bit variables with 32-bit
 * hash word). Produces and returns hash of the specified message. This
 * function is designed for 32 to 256-bit hashes due to state variable size.
 * Technically, it works similarly to the "full" PRVHASH variants, but
 * structurally is very different.
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[out] Hash The resulting hash. The length of this buffer should be
 * equal to HashLen. On systems where this is relevant, this address should be
 * aligned to 32 bits. The resulting hash will not be endianness-corrected.
 * @param HashLen The required hash length, in bytes, should be >= 4, in
 * increments of 4.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. The SeedXOR value can have any bit length, and is
 * used only as an additional entropy source.
 */

inline void prvhash42f( const uint8_t* Msg, size_t MsgLen,
	uint8_t* Hash, size_t HashLen, const uint64_t SeedXOR )
{
	uint64_t Seed1 = 12905183526369792234ULL ^ SeedXOR;
	uint64_t Seed2 = 6447574768757703757ULL;
	uint64_t Seed3 = 16194475384935965921ULL;
	uint64_t Seed4 = 2089449202563329443ULL;

	uint64_t fbm = 0;

	if( MsgLen > 0 )
	{
		fbm -= ( ~Msg[ MsgLen - 1 ] >> 7 ) & 1;
	}

	const uint8_t* const MsgEnd = Msg + MsgLen;
	int sc = 1 + (( MsgLen & 31 ) == 0 );

	while( 1 )
	{
		uint64_t v1, v2, v3, v4;

		if( MsgLen > 31 )
		{
			v1 = prvhash42_u64ec( Msg );
			v2 = prvhash42_u64ec( Msg + 8 );
			v3 = prvhash42_u64ec( Msg + 16 );
			v4 = prvhash42_u64ec( Msg + 24 );
			MsgLen -= 32;
			Msg += 32;
		}
		else
		if( MsgLen > 23 )
		{
			v1 = prvhash42_u64ec( Msg );
			v2 = prvhash42_u64ec( Msg + 8 );
			v3 = prvhash42_u64ec( Msg + 16 );
			v4 = prvhash42_lp64( Msg + 24, MsgEnd, (uint8_t) fbm );
			MsgLen = 0;
		}
		else
		if( MsgLen > 15 )
		{
			v1 = prvhash42_u64ec( Msg );
			v2 = prvhash42_u64ec( Msg + 8 );
			v3 = prvhash42_lp64( Msg + 16, MsgEnd, (uint8_t) fbm );
			v4 = fbm;
			MsgLen = 0;
		}
		else
		if( MsgLen > 7 )
		{
			v1 = prvhash42_u64ec( Msg );
			v2 = prvhash42_lp64( Msg + 8, MsgEnd, (uint8_t) fbm );
			v3 = fbm;
			v4 = fbm;
			MsgLen = 0;
		}
		else
		if( MsgLen > 0 )
		{
			v1 = prvhash42_lp64_1( Msg, MsgEnd, (uint8_t) fbm );
			v2 = fbm;
			v3 = fbm;
			v4 = fbm;
			MsgLen = 0;
		}
		else
		{
			v1 = fbm;
			v2 = fbm;
			v3 = fbm;
			v4 = fbm;
			sc--;
		}

		v1 ^= Seed4;
		v2 ^= Seed1;
		v3 ^= Seed2;
		v4 ^= Seed3;
		v1 *= Seed1 - ~Seed1;
		v2 *= Seed2 - ~Seed2;
		v3 *= Seed3 - ~Seed3;
		v4 *= Seed4 - ~Seed4;
		Seed1 = v1 ^ v1 >> 32;
		Seed2 = v2 ^ v2 >> 32;
		Seed3 = v3 ^ v3 >> 32;
		Seed4 = v4 ^ v4 >> 32;

		if( sc < 0 )
		{
			*(uint32_t*) Hash = (uint32_t) ( Seed1 ^ Seed2 ^ Seed3 ^ Seed4 );

			if( HashLen == 4 )
			{
				return;
			}

			HashLen -= 4;
			Hash += 4;
		}
	}
}

#endif // PRVHASH42F_INCLUDED

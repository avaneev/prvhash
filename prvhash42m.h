/**
 * prvhash42m.h version 2.30
 *
 * The inclusion file for the "prvhash42m" hash function, specially designed
 * for table hash use (due to small size).
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
 * hash of the specified message. This function does not apply endianness
 * correction. This is a "minimal" implementation that uses PRVHASH's property
 * of PRNG period extension due to entropy input. Designed for table hash use.
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[in,out] Hash The resulting hash. The length of this buffer should be
 * equal to HashLen. On systems where this is relevant, this address should be
 * aligned to 32 bits.
 * @param HashLen The required hash length, in bytes, should be >= 4, in
 * increments of 4.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0. The SeedXOR value can have any bit length, and is
 * used only as an additional entropy source. It should be
 * endianness-corrected.
 */

inline void prvhash42m( const uint8_t* Msg, const int MsgLen,
	uint8_t* Hash, int HashLen, const uint64_t SeedXOR )
{
	uint64_t Seed = 12905183526369792234ULL ^ SeedXOR;
	uint64_t lcg = 6447574768757703757ULL;
	uint32_t HashVal = 0;

	const uint64_t fbm = 0ULL - (uint64_t) (( ~Msg[ MsgLen - 1 ] >> 7 ) & 1 );
	const uint8_t* const MsgEnd = Msg + MsgLen;
	int sc = (( MsgLen & 7 ) == 0 ? 2 : 1 );

	while( true )
	{
		if( Msg < MsgEnd )
		{
			if( Msg < MsgEnd - 7 )
			{
				lcg ^= prvhash42_u64ec( Msg );
			}
			else
			{
				const uint8_t fb = (uint8_t) fbm;

				lcg ^= prvhash42_lp32_1( Msg, MsgEnd, fb ) |
					(uint64_t) prvhash42_lp32( Msg + 4, MsgEnd, fb ) << 32;
			}

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
			*(uint32_t*) Hash = h;

			if( HashLen <= 4 )
			{
				break;
			}

			Hash += 4;
			HashLen -= 4;
		}
	}
}

#endif // PRVHASH42M_INCLUDED

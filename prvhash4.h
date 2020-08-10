//$ nocpp

/**
 * @file prvhash4.h
 *
 * @brief The inclusion file for the "prvhash4" hash function.
 *
 * @mainpage
 *
 * @section intro_sec Introduction
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * @section license License
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
 *
 * @version 1.0
 */

#ifndef PRVHASH4_INCLUDED
#define PRVHASH4_INCLUDED

#include <stdint.h>
#include <string.h>

/**
 * PRVHASH hash function (64-bit with 32-bit hash word). Produces hash of the
 * specified Message.
 *
 * @param Message Message to produce hash from.
 * @param MessageLen Message length.
 * @param[out] Hash The resulting hash.
 * @param HashLen The required hash length, in bytes, should be >= 1.
 * @param SeedXOR Optional value, to XOR the default seed with.
 * @param InitLCG For development purposes. If != 0, "lcg" value to use.
 * @param InitSeed For development purposes. If != 0, "Seed" value to use.
 */

inline void prvhash4( const uint8_t* const Message, const int MessageLen,
	uint8_t* const Hash, const int HashLen, const uint64_t SeedXOR = 0,
	const uint64_t InitLCG = 0, const uint64_t InitSeed = 0 )
{
	// Initialize hash position remapping table for non-power-of-2 hash
	// lengths.

	size_t PosTable[ 16 ];
	int p = 0;
	int i;

	for( i = 0; i < 16; i++ )
	{
		PosTable[ i ] = ( p << 2 );
		p++;

		if( p == ( HashLen >> 2 ))
		{
			p = 0;
		}
	}

	// Initialize the hash.

	memset( Hash, 0, HashLen );

	uint64_t lcg = ( InitLCG == 0 ? 15267459991392010589ULL : InitLCG );
		// Multiplier inspired by LCG. This is not a prime number. It is a
		// random sequence of bits. This value can be regenerated at will,
		// possibly using various statistical search methods. The best
		// strategies: 1) Compose both this and seed numbers of 8-bit values
		// that have 4 random bits set; 2) Compose the 64-bit value that has
		// 32 random bits set; same for seed.

	uint64_t Seed = ( InitSeed == 0 ? 7928988912013905173ULL : InitSeed );
		// Generated similarly to "lcg".

	Seed ^= SeedXOR;
	int k;

	for( k = 0; k < MessageLen; k++ )
	{
		const uint64_t m = Message[ k ];

		const size_t HashPos = (size_t) ( Seed >> 60 ); // Use higher bits.
		Seed *= lcg;
		const uint32_t* const h = (uint32_t*) &Hash[ PosTable[ HashPos ]];
		Seed += m * ( (uint64_t) *h + 1 );

		for( i = 0; i < HashLen; i += 4 )
		{
			Seed *= lcg;
			uint32_t* const hc = (uint32_t*) &Hash[ i ];
			const uint64_t ph = (uint64_t) *hc;
			*hc ^= (uint32_t) ( Seed >> 32 );
			Seed ^= ph ^ m;
		}

		lcg += Seed;
	}
}

#endif // PRVHASH4_INCLUDED

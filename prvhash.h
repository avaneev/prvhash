//$ nocpp

/**
 * @file prvhash.h
 *
 * @brief The inclusion file for the PRVHASH hash function.
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
 */

#ifndef PRVHASH_INCLUDED
#define PRVHASH_INCLUDED

#include <stdint.h>

/**
 * PRVHASH hash function. Produces hash of the specified Message.
 *
 * @param Message Message to produce hash from.
 * @param MessageLen Message length.
 * @param[out] Hash The resulting hash.
 * @param HashLen The required hash length, in bytes, should be >= 1.
 * @param SeedXOR Optional value, to XOR the default seed with.
 */

inline void prvhash( const uint8_t* const Message, const int MessageLen,
	uint8_t* const Hash, const int HashLen, const uint32_t SeedXOR = 0 )
{
	// Initialize hash position remapping table for non-power-of-2 hash
	// lengths.

	size_t PosTable[ 64 ];
	int p = 0;
	int i;

	for( i = 0; i < 64; i++ )
	{
		PosTable[ i ] = p;
		p++;

		if( p == HashLen )
		{
			p = 0;
		}
	}

	// Initialize the hash.

	for( i = 0; i < HashLen; i++ )
	{
		Hash[ i ] = 0;
	}

	uint32_t lcg1 = 2198191546UL; // Multiplier inspired by LCG. This is not a
		// prime number. It is a random sequence of bits. This value can be
		// regenerated at will, possibly using various statistical search
		// methods. The best strategies: 1) Compose both this and seed numbers
		// of 8-bit values that have 4 random bits set; 2) Compose the 32-bit
		// value that has 16 random bits set; same for seed.

	uint32_t Seed = 488279453UL; // Generated similarly to "lcg1".

	Seed ^= SeedXOR;
	int k;

	for( k = 0; k < MessageLen; k++ )
	{
		const uint32_t m = (uint8_t) Message[ k ];

		const size_t HashPos = (uint8_t) ( Seed >> 26 ); // Use higher bits.
		Seed *= lcg1;
		Seed += m * ( (uint32_t) Hash[ PosTable[ HashPos ]] + 1 );

		for( i = 0; i < HashLen; i++ )
		{
			Seed *= lcg1;
			const uint32_t t = (uint32_t) Hash[ i ] ^ m;
			Hash[ i ] ^= (uint8_t) ( Seed >> 24 );
			Seed ^= t;
		}

		lcg1 += Seed;
	}
}

#endif // PRVHASH_INCLUDED

/**
 * @file prvhash42opt.h
 *
 * @brief The inclusion file for the "prvhash42" hash function, optimized for
 * 32-bit hash length, without endianness-correction.
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
 * @version 2.6
 */

//$ nocpp

#ifndef PRVHASH42OPT_INCLUDED
#define PRVHASH42OPT_INCLUDED

#include <stdint.h>

/**
 * Optimized PRVHASH hash function. Produces 32-bit hash of the specified
 * Message using default initial "Hash", "lcg" and "Seed" values.
 *
 * @param Message Message to produce hash from.
 * @param MessageLen Message length, in bytes.
 * @param[out] Hash The resulting hash, 32-bit, not endianness-corrected.
 * @param SeedXOR Optional value, to XOR the default seed with. To use the
 * default seed, set to 0.
 */

inline void prvhash42_32( const uint8_t* const Message, const int MessageLen,
	uint8_t* const Hash0, const uint64_t SeedXOR )
{
	uint64_t Hash = 0;
	uint64_t lcg = 15267459991392010589ULL;
	uint64_t Seed = 7928988912013905173ULL ^ SeedXOR;

	int k;

	for( k = 0; k < MessageLen; k++ )
	{
		const uint64_t msg = Message[ k ];

		Seed *= lcg;
		const uint64_t ph = Hash;
		Hash ^= Seed >> 32;
		Seed ^= ph ^ msg;
		lcg += Seed;
	}

	Seed *= lcg;
	const uint64_t ph = Hash;
	Hash ^= Seed >> 32;
	Seed ^= ph ^ 0x100;
	lcg += Seed;

	Seed *= lcg;
	Hash ^= Seed >> 32;

	*(uint32_t*) Hash0 = (uint32_t) Hash;
}

/**
 * This function corrects endianness of the resulting prvhash42 hash. This
 * function may be called both after and before hashing session. Works only on
 * little- and big-endian systems.
 *
 * @param[in,out] Hash The hash.
 * @param HashLen The hash length, in bytes, should be >= 4, in increments of
 * 4.
 */

inline void prvhash42_cend( uint8_t* const Hash, const int HashLen )
{
	int e = 1;

	if( *(uint8_t*) &e != 0 )
	{
		return;
	}

	int i;

	for( i = 0; i < HashLen; i += 4 )
	{
		const uint8_t h0 = Hash[ i + 0 ];
		const uint8_t h1 = Hash[ i + 1 ];
		Hash[ i + 0 ] = Hash[ i + 3 ];
		Hash[ i + 1 ] = Hash[ i + 2 ];
		Hash[ i + 2 ] = h1;
		Hash[ i + 3 ] = h0;
	}
}

/**
 * This function corrects endianness of the resulting prvhash82 hash. This
 * function may be called both after and before hashing session. Works only on
 * little- and big-endian systems.
 *
 * @param[in,out] Hash The hash.
 * @param HashLen The hash length, in bytes, should be >= 8, in increments of
 * 8.
 */

inline void prvhash82_cend( uint8_t* const Hash, const int HashLen )
{
	int e = 1;

	if( *(uint8_t*) &e != 0 )
	{
		return;
	}

	int i;

	for( i = 0; i < HashLen; i += 8 )
	{
		const uint8_t h0 = Hash[ i + 0 ];
		const uint8_t h1 = Hash[ i + 1 ];
		const uint8_t h2 = Hash[ i + 2 ];
		const uint8_t h3 = Hash[ i + 3 ];
		Hash[ i + 0 ] = Hash[ i + 7 ];
		Hash[ i + 1 ] = Hash[ i + 6 ];
		Hash[ i + 2 ] = Hash[ i + 5 ];
		Hash[ i + 3 ] = Hash[ i + 4 ];
		Hash[ i + 4 ] = h3;
		Hash[ i + 5 ] = h2;
		Hash[ i + 6 ] = h1;
		Hash[ i + 7 ] = h0;
	}
}

#endif // PRVHASH42OPT_INCLUDED

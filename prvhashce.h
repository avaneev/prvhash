/**
 * @file prvhashce.h
 *
 * @brief The inclusion file for endianness-correction functions.
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
 * @version 2.7
 */

//$ nocpp

#ifndef PRVHASHCE_INCLUDED
#define PRVHASHCE_INCLUDED

#include <stdint.h>

/**
 * This function corrects endianness of the resulting prvhash42 hash. This
 * function may be called both after and before hashing session. Works only on
 * little- and big-endian systems.
 *
 * @param[in,out] Hash The hash.
 * @param HashLen The hash length, in bytes, should be >= 4, in increments of
 * 4.
 */

inline void prvhash42_ce( uint8_t* const Hash, const int HashLen )
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

inline void prvhash82_ce( uint8_t* const Hash, const int HashLen )
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

#endif // PRVHASHCE_INCLUDED

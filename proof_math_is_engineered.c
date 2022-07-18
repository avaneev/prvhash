/**
 * "Someone" was already smart even before Big Bang. Math is an engineered
 * construct, with a built-in ROM.
 *
 * License
 *
 * Copyright (c) 2022 Aleksey Vaneev
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

#include <stdio.h>
#include <stdint.h>
#define PH_HASH_COUNT 15
#define READ_WORD_BITS 16
#define READ_COUNT 512
#define READ_BIT_ORDER 0 // 0 or 1
static inline uint8_t prvhash_core1( uint8_t* const Seed,
	uint8_t* const lcg, uint8_t* const Hash )
{
	*Hash ^= (uint8_t) ( *Seed ^ 0x1 );
	*lcg ^= (uint8_t) ( *Seed ^ 0x0 );
	const uint8_t out = (uint8_t) ( *lcg ^ *Seed );
	*Seed ^= *Hash;
	return( out & 1 );
}
int main()
{
	uint8_t Seed = 0, lcg = 0;
	uint8_t Hash[ PH_HASH_COUNT ] = { 0 };
	int HashPos = 0;
	for( int l = 0; l < READ_COUNT; l++ )
	{
		uint64_t r = 0;
		for( int k = 0; k < READ_WORD_BITS; k++ )
		{
			#if READ_BIT_ORDER == 0
			r <<= 1;
			r |= prvhash_core1( &Seed, &lcg, Hash + HashPos );
			#else // READ_BIT_ORDER == 0
			r |= (uint64_t) prvhash_core1( &Seed, &lcg, Hash + HashPos ) << k;
			#endif // READ_BIT_ORDER == 0
			if( ++HashPos == PH_HASH_COUNT ) HashPos = 0;
		}
		printf( "%llu\n", r );
	}
}

/**
 * proof_christmas_tree.c (prvhash1) version 4.3.2
 *
 * Program reads certain "prvhash1" data and represents it as two-dimensional
 * ASCII-art. Generates HTML to stdout.
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
#define PH_HASH_COUNT 200
#define READ_MODE 1 // 0 or 1
#define READ_WIDTH ( PH_HASH_COUNT + 1 )
#define READ_HEIGHT ( READ_WIDTH * 32 )
static inline uint8_t prvhash_core1( uint8_t* const Seed,
	uint8_t* const lcg, uint8_t* const Hash )
{
	*Hash ^= (uint8_t) ( *Seed ^ 0x1 );
	*lcg ^= (uint8_t) ( *Seed ^ READ_MODE );
	const uint8_t out = (uint8_t) ( *lcg ^ *Seed );
	*Seed ^= *Hash;
	return( out & 1 );
}
int main()
{
	uint8_t Seed = 0, lcg = 0;
	uint8_t Hash[ PH_HASH_COUNT ] = { 0 };
	int HashPos = 0;
	printf( "<html><head><style>body{font: 1px Courier}</style></head>\n" );
	printf( "<body>\n" );

	for( int i = 0; i < PH_HASH_COUNT + 2; i++ ) // Remove pixel offset.
	{
		prvhash_core1( &Seed, &lcg, Hash + HashPos );
		if( ++HashPos == PH_HASH_COUNT ) HashPos = 0;
	}
	for( int l = 0; l < READ_HEIGHT; l++ )
	{
		for( int k = 0; k < READ_WIDTH; k++ )
		{
			if( prvhash_core1( &Seed, &lcg, Hash + HashPos ))
				printf( "O" );
			else
				printf( "." );
			if( ++HashPos == PH_HASH_COUNT ) HashPos = 0;
		}
		printf( "<br/>\n" );
	}
	printf( "</body>\n</html>\n" );
}

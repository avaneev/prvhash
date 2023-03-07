/**
 * proof_reptile.c (prvhash1) version 4.3.1
 *
 * Program reads "prvhash1" data and builds a black-and-white image using
 * multi-pass approach. Produces a JPG image using "stb_image_write" library.
 * 
 * License
 *
 * Copyright (c) 2022-2023 Aleksey Vaneev
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

#include <stdint.h>
// !!! Requires "stb_image_write.h" from https://github.com/nothings/stb
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#define PH_HASH_COUNT 2046 // 1365, 1366, 1638, or 2046
#define PH_SEED_COUNT 32 // 1-4, powers of 2
#define WIDTH ( PH_HASH_COUNT + 1 )
#define HEIGHT 2048
#define CHN 3
#define PASS_COUNT 127
#define MSH 1
static inline uint8_t prvhash_core1_min( uint8_t* const Seed,
	uint8_t* const Hash )
{
	*Hash ^= (uint8_t) ( *Seed ^ 1 );
	const uint8_t out = *Seed;
	*Seed ^= *Hash;
	return( out );
}
int main()
{
	uint8_t Seed[ PH_SEED_COUNT ] = { 0 };
	uint8_t Hash[ PH_HASH_COUNT ] = { 0 };
	int i, HashPos = 0, SeedPos = 0;

	uint8_t* img = (uint8_t*) malloc( WIDTH * HEIGHT * CHN );
	memset( img, 0, WIDTH * HEIGHT * CHN );
	for( i = 0; i < PASS_COUNT; i++ )
	{
		uint8_t* op = img;
		for( int l = 0; l < WIDTH * HEIGHT; l++ )
		{
			op[ 0 ] += prvhash_core1_min( Seed + SeedPos, Hash + HashPos ) << MSH;
			op[ 1 ] = op[ 0 ];
			op[ 2 ] = op[ 1 ];
			if( ++HashPos == PH_HASH_COUNT ) HashPos = 0;
			if( ++SeedPos == PH_SEED_COUNT ) SeedPos = 0;
			op += CHN;
		}
	}
	stbi_write_jpg( "prvhash1-2048.jpg", WIDTH, HEIGHT, CHN, img, 95 );
	free( img );
}

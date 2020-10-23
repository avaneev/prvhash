/**
 * @file prvrng.h
 *
 * @brief The inclusion file for the "prvrng" entropy pseudo-random number
 * generator.
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
 * @version 2.25
 */

//$ nocpp
//$ lib "win*|AdvAPI32"

#ifndef PRVRNG_INCLUDED
#define PRVRNG_INCLUDED

#include <stdio.h>
#include "prvhash42core.h"

#if defined( _WIN32 ) || defined( _WIN64 )
	#include <windows.h>
	#include <wincrypt.h>
#else // defined( _WIN32 ) || defined( _WIN64 )
	#define PRVRNG_UNIX 1
#endif // defined( _WIN32 ) || defined( _WIN64 )

/**
 * prvrng context structure.
 */

#define PRVRNG_PAR_COUNT 2 // PRNG parallelism.
#define PRVRNG_HASH_WORD_COUNT 16 // Hashwords in a hasharray.

typedef struct
{
	#if defined( PRVRNG_UNIX )
		FILE* f; ///< /dev/random file.
	#else // defined( PRVRNG_UNIX )
		HCRYPTPROV prov; ///< Crypt provider (for Windows).
	#endif // defined( PRVRNG_UNIX )

	uint64_t Seed[ PRVRNG_PAR_COUNT ]; ///< Current Seed values.
	uint64_t lcg[ PRVRNG_PAR_COUNT ]; ///< Current lcg values.
	uint32_t Hash[ PRVRNG_HASH_WORD_COUNT ]; ///< Current hash values.
	int HashPos; ///< Position within the Hash array.
	int EntCtr; ///< Bytes remaining before entropy is injected.
	int OutLeft; ///< Bytes left in LastOut.
	uint32_t LastOut; ///< Previously generated output.
} PRVRNG_CTX;

/**
 * Internal function returns a "true" entropy 16-bit word. This is simulated
 * by obtaining a byte from /dev/random or Windows' CryptGenRandom().
 *
 * @param ctx Pointer to the context structure.
 */

inline uint16_t prvrng_gen_entropy16( PRVRNG_CTX* const ctx )
{
	uint16_t val = 0;

	#if defined( PRVRNG_UNIX )

		fread( &val, 1, 2, ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptGenRandom( ctx -> prov, 2, (uint8_t*) &val );

	#endif // defined( PRVRNG_UNIX )

	return( val );
}

/**
 * This function calculates bit count of a 16-bit number, in a platform
 * independent way.
 *
 * @param v Value.
 */

inline int prvrng_popcnt_u16( const uint16_t v )
{
	return(( v & 1 ) + (( v >> 1 ) & 1 ) + (( v >> 2 ) & 1 ) +
		(( v >> 3 ) & 1 ) + (( v >> 4 ) & 1 ) + (( v >> 5 ) & 1 ) +
		(( v >> 6 ) & 1 ) + (( v >> 7 ) & 1 ) + (( v >> 8 ) & 1 ) +
		(( v >> 9 ) & 1 ) + (( v >> 10 ) & 1 ) + (( v >> 11 ) & 1 ) +
		(( v >> 12 ) & 1 ) + (( v >> 13 ) & 1 ) + (( v >> 14 ) & 1 ) +
		( v >> 15 ));
}

/**
 * Function generates an N-bit entropy value and assures this value is
 * composed of "c" 16-bit values that each have 4 to 12 bits set. This
 * function is required to generate a stable initial state of the hash
 * function. This constraint is usually quickly satisfied.
 *
 * @param ctx Pointer to the context structure.
 * @param c The number of 16-bit values to produce (4 for 64-bit value,
 * 2 for 32-bit value).
 */

inline uint64_t prvrng_gen_entropy_c16( PRVRNG_CTX* const ctx, const int c )
{
	uint64_t val = 0;
	int j;

	for( j = 0; j < c; j++ )
	{
		while( true )
		{
			const uint16_t tv = prvrng_gen_entropy16( ctx );
			const int bcnt = prvrng_popcnt_u16( tv );

			if( bcnt >= 4 && bcnt <= 12 )
			{
				val <<= 16;
				val |= tv;
				break;
			}
		}
	}

	return( val );
}

/**
 * Function generates the next random 8-bit number.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen64p2( PRVRNG_CTX* const ctx )
{
	if( ctx -> OutLeft == 0 )
	{
		if( ctx -> EntCtr == 0 )
		{
			const uint16_t v = prvrng_gen_entropy16( ctx );
			ctx -> EntCtr = (( v & 0xFF ) + 1 ) << 2;
			ctx -> lcg[ 0 ] ^= ( v >> 8 ) + 1;
		}

		uint32_t& Hash = ctx -> Hash[ ctx -> HashPos ];
		int i;

		for( i = 0; i < PRVRNG_PAR_COUNT - 1; i++ )
		{
			prvhash42_core64( ctx -> Seed[ i ], ctx -> lcg[ i ], Hash );
		}

		ctx -> LastOut = prvhash42_core64( ctx -> Seed[ i ],
			ctx -> lcg[ i ], Hash );

		ctx -> HashPos++;

		if( ctx -> HashPos == PRVRNG_HASH_WORD_COUNT )
		{
			ctx -> HashPos = 0;
		}

		ctx -> OutLeft = 4;
		ctx -> EntCtr--;
	}

	const uint8_t r = (uint8_t) ctx -> LastOut;
	ctx -> LastOut >>= 8;
	ctx -> OutLeft--;

	return( r );
}

/**
 * Function initalizes the entropy PRNG context. It also seeds the generator
 * with the initial entropy.
 *
 * @param ctx Pointer to the context structure.
 * @return 0 if failed.
 */

inline int prvrng_init64p2( PRVRNG_CTX* const ctx )
{
	#if defined( PRVRNG_UNIX )

		ctx -> f = fopen( "/dev/random", "rb" );

		if( ctx -> f == NULL )
		{
			return( 0 );
		}

	#else // defined( PRVRNG_UNIX )

		if( !CryptAcquireContext( &ctx -> prov, NULL, NULL, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT ))
		{
			return( 0 );
		}

	#endif // defined( PRVRNG_UNIX )

	int i;

	for( i = 0; i < PRVRNG_PAR_COUNT; i++ )
	{
		ctx -> Seed[ i ] = prvrng_gen_entropy_c16( ctx, 4 );
		ctx -> lcg[ i ] = prvrng_gen_entropy_c16( ctx, 4 );
	}

	for( i = 0; i < PRVRNG_HASH_WORD_COUNT; i++ )
	{
		ctx -> Hash[ i ] = (uint32_t) prvrng_gen_entropy_c16( ctx, 2 );
	}

	ctx -> HashPos = 0;
	ctx -> EntCtr = 0;
	ctx -> OutLeft = 0;
	ctx -> LastOut = 0;

	return( 1 );
}

/**
 * Function deinitializes the PRNG, for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline void prvrng_final64p2( PRVRNG_CTX* ctx )
{
	#if defined( PRVRNG_UNIX )

		fclose( ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptReleaseContext( ctx -> prov, 0 );

	#endif // defined( PRVRNG_UNIX )
}

/**
 * A test function for "prvrng", 32-bit hash-based. Prints 16 random bytes.
 */

inline void prvrng_test64p2()
{
	PRVRNG_CTX ctx;

	if( !prvrng_init64p2( &ctx ))
	{
		printf( "Cannot obtain the entropy source!\n" );
		return;
	}

	int i;

	for( i = 0; i < 16; i++ )
	{
		printf( "%i\n", (int) prvrng_gen64p2( &ctx ));
	}

	prvrng_final64p2( &ctx );
}

#endif // PRVRNG_INCLUDED

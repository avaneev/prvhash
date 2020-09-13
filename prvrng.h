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
 * @version 2.21
 */

//$ nocpp
//$ lib "win*|AdvAPI32"

#ifndef PRVRNG_INCLUDED
#define PRVRNG_INCLUDED

#include <stdint.h>
#include <stdio.h>

#if defined( _WIN32 ) || defined( _WIN64 )
	#include <windows.h>
	#include <wincrypt.h>
#else // defined( _WIN32 ) || defined( _WIN64 )
	#define PRVRNG_UNIX 1
#endif // defined( _WIN32 ) || defined( _WIN64 )

/**
 * prvrng context structure.
 */

typedef struct
{
	#if defined( PRVRNG_UNIX )
		FILE* f; ///< /dev/random file.
	#else // defined( PRVRNG_UNIX )
		HCRYPTPROV prov; ///< Crypt provider (for Windows).
	#endif // defined( PRVRNG_UNIX )

	uint64_t lcg[ 2 ]; ///< Current lcg values.
	uint64_t Seed[ 2 ]; ///< Current Seed values.
	uint64_t Hash[ 2 ]; ///< Current 32-bit hash values.
	int EntCtr; ///< Bytes remaining before entropy is injected.
	int HashLeft; ///< Bytes left in hash.
	uint64_t LastHash; ///< Previously generated hash.
} PRVRNG_CTX;

/**
 * Internal function returns a "true" entropy byte. This is simulated by
 * obtaining a byte from /dev/random or Windows' CryptGenRandom().
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen_entropy( PRVRNG_CTX* const ctx )
{
	uint8_t val = 0;

	#if defined( PRVRNG_UNIX )

		fread( &val, 1, 1, ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptGenRandom( ctx -> prov, 1, &val );

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
			uint16_t tv = (uint16_t) prvrng_gen_entropy( ctx );
			tv <<= 8;
			tv |= (uint16_t) prvrng_gen_entropy( ctx );

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
 * Internal function, calculates "prvhash42" round with parallel structure,
 * for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 * @param Hash Hash word.
 * @param msgw Entropy message word (up to 32 bits).
 */

inline void prvrng_prvhash42_32p2( PRVRNG_CTX* const ctx, uint64_t& Hash,
	const uint64_t msgw )
{
	ctx -> Seed[ 0 ] *= ctx -> lcg[ 0 ];
	ctx -> Seed[ 1 ] *= ctx -> lcg[ 1 ];
	ctx -> Seed[ 0 ] = ~ctx -> Seed[ 0 ];
	ctx -> Seed[ 1 ] = ~ctx -> Seed[ 1 ];
	const uint64_t hl0 = ctx -> lcg[ 0 ] >> 32 ^ msgw;
	const uint64_t hl1 = ctx -> lcg[ 1 ] >> 32;
	ctx -> lcg[ 0 ] += ctx -> Seed[ 0 ];
	ctx -> lcg[ 1 ] += ctx -> Seed[ 1 ];

	Hash ^= ctx -> Seed[ 0 ] >> 32;
	ctx -> Seed[ 0 ] ^= Hash ^ hl0;

	Hash ^= ctx -> Seed[ 1 ] >> 32;
	ctx -> Seed[ 1 ] ^= Hash ^ hl1;
}

/**
 * Function generates the next random 8-bit number, for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen64p2( PRVRNG_CTX* const ctx )
{
	if( ctx -> HashLeft == 0 )
	{
		uint64_t msgw;

		if( ctx -> EntCtr == 0 )
		{
			ctx -> EntCtr = ( (int) prvrng_gen_entropy( ctx ) + 1 ) << 2;
			msgw = prvrng_gen_entropy( ctx );
		}
		else
		{
			msgw = 0;
		}

		int i;

		for( i = 0; i < 2; i++ )
		{
			if( ctx -> lcg[ 0 ] == 0 )
			{
				ctx -> lcg[ 0 ] = prvrng_gen_entropy_c16( ctx, 4 );
			}

			if( ctx -> lcg[ 1 ] == 0 )
			{
				ctx -> lcg[ 1 ] = prvrng_gen_entropy_c16( ctx, 4 );
			}

			prvrng_prvhash42_32p2( ctx, ctx -> Hash[ i ], msgw );
			msgw = 0;
		}

		ctx -> HashLeft = 8;
		ctx -> LastHash = ctx -> Hash[ 0 ] | ctx -> Hash[ 1 ] << 32;
		ctx -> EntCtr--;
	}

	const uint8_t r = (uint8_t) ctx -> LastHash;
	ctx -> LastHash >>= 8;
	ctx -> HashLeft--;

	return( r );
}

/**
 * Function initalizes the entropy PRNG context, for 32-bit hash. It also
 * seeds the generator with initial entropy.
 *
 * @param ctx Pointer to the context structure.
 * @param DoPreInit Pre-initialize the PRNG with the entropy source.
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

	for( i = 0; i < 2; i++ )
	{
		ctx -> lcg[ i ] = prvrng_gen_entropy_c16( ctx, 4 );
		ctx -> Seed[ i ] = prvrng_gen_entropy_c16( ctx, 4 );
		ctx -> Hash[ i ] = prvrng_gen_entropy_c16( ctx, 2 );
	}

	ctx -> EntCtr = 0;
	ctx -> HashLeft = 0;
	ctx -> LastHash = 0;

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

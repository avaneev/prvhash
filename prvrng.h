/**
 * prvrng.h version 3.3
 *
 * The inclusion file for the "prvrng" entropy pseudo-random number generator.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020-2021 Aleksey Vaneev
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

//$ lib "win*|AdvAPI32"

#ifndef PRVRNG_INCLUDED
#define PRVRNG_INCLUDED

#include <stdio.h>
#include "prvhash_core.h"
#include "prvhash_aux.h"

#if defined( _WIN32 )
	#include <windows.h>
	#include <wincrypt.h>
#else // defined( _WIN32 )
	#define PRVRNG_UNIX 1
#endif // defined( _WIN32 )

/**
 * prvrng context structure.
 */

#define PRVRNG_PAR_COUNT 2 // PRNG parallelism.
#define PRVRNG_HASH_COUNT 16 // Hashwords in a hasharray.

typedef struct
{
	#if defined( PRVRNG_UNIX )
		FILE* f; ///< /dev/random file.
	#else // defined( PRVRNG_UNIX )
		HCRYPTPROV prov; ///< Crypt provider (for Windows).
	#endif // defined( PRVRNG_UNIX )

	uint64_t Seed[ PRVRNG_PAR_COUNT ]; ///< Current Seed values.
	uint64_t lcg[ PRVRNG_PAR_COUNT ]; ///< Current lcg values.
	uint64_t Hash[ PRVRNG_HASH_COUNT ]; ///< Current hash values.
	size_t HashPos; ///< Position within the Hash array.
	int EntCtr; ///< Bytes remaining before entropy is injected.
	size_t OutLeft; ///< Bytes left in LastOut.
	uint64_t LastOut; ///< Previously generated output.
} PRVRNG_CTX;

/**
 * Internal function returns a "true" entropy value. This is simulated
 * by obtaining a byte from /dev/random or Windows' CryptGenRandom().
 *
 * @param ctx Pointer to the context structure.
 * @param c The number of bytes to return, 1 to 8.
 */

inline uint64_t prvrng_gen_entropy( PRVRNG_CTX* const ctx, const size_t c )
{
	uint8_t val[ 8 ];
	memset( val, 0, sizeof( val ));

	#if defined( PRVRNG_UNIX )

		fread( val, 1, c, ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptGenRandom( ctx -> prov, (DWORD) c, val );

	#endif // defined( PRVRNG_UNIX )

	return( prvhash_lu64ec( val ));
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
			const uint16_t v = (uint16_t) prvrng_gen_entropy( ctx, 2 );
			ctx -> EntCtr = ( v & 0xFF ) + 1;
			ctx -> lcg[ 0 ] ^= ( v >> 8 ) + 1;
		}

		uint64_t* const Hash = ctx -> Hash + ctx -> HashPos;
		int i;

		for( i = 0; i < PRVRNG_PAR_COUNT - 1; i++ )
		{
			prvhash_core64( &ctx -> Seed[ i ], &ctx -> lcg[ i ], Hash );
		}

		ctx -> LastOut =
			prvhash_core64( &ctx -> Seed[ i ], &ctx -> lcg[ i ], Hash );

		ctx -> HashPos++;

		if( ctx -> HashPos == PRVRNG_HASH_COUNT )
		{
			ctx -> HashPos = 0;
		}

		ctx -> OutLeft = sizeof( ctx -> LastOut );
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
		ctx -> Seed[ i ] = prvrng_gen_entropy( ctx, sizeof( uint64_t ));
		ctx -> lcg[ i ] = prvrng_gen_entropy( ctx, sizeof( uint64_t ));
	}

	for( i = 0; i < PRVRNG_HASH_COUNT; i++ )
	{
		ctx -> Hash[ i ] = prvrng_gen_entropy( ctx, sizeof( uint64_t ));
	}

	ctx -> HashPos = 0;
	ctx -> EntCtr = 0;
	ctx -> OutLeft = 0;
	ctx -> LastOut = 0;

	int k;

	for( k = 0; k < PRVRNG_HASH_COUNT; k++ )
	{
		uint64_t* const Hash = ctx -> Hash + k;
		int i;

		for( i = 0; i < PRVRNG_PAR_COUNT; i++ )
		{
			prvhash_core64( &ctx -> Seed[ i ], &ctx -> lcg[ i ], Hash );
		}
	}

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

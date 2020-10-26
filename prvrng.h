/**
 * prvrng.h version 2.27
 *
 * The inclusion file for the "prvrng" entropy pseudo-random number generator.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * Copyright (c) 2020 Aleksey Vaneev; All rights reserved.
 */

//$ lib "win*|AdvAPI32"

#ifndef PRVRNG_INCLUDED
#define PRVRNG_INCLUDED

#include <stdio.h>
#include "prvhash42core.h"
#include "prvhash42ec.h"

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

	return( prvhash42_u64ec( val ));
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
		ctx -> Seed[ i ] = prvrng_gen_entropy( ctx, 8 );
		ctx -> lcg[ i ] = prvrng_gen_entropy( ctx, 8 );
	}

	for( i = 0; i < PRVRNG_HASH_WORD_COUNT; i++ )
	{
		ctx -> Hash[ i ] = (uint32_t) prvrng_gen_entropy( ctx, 4 );
	}

	ctx -> HashPos = 0;
	ctx -> EntCtr = 0;
	ctx -> OutLeft = 0;
	ctx -> LastOut = 0;

	int k;

	for( k = 0; k < 5; k++ )
	{
		uint32_t& Hash = ctx -> Hash[ ctx -> HashPos ];
		int i;

		for( i = 0; i < PRVRNG_PAR_COUNT; i++ )
		{
			prvhash42_core64( ctx -> Seed[ i ], ctx -> lcg[ i ], Hash );
		}

		ctx -> HashPos++;

		if( ctx -> HashPos == PRVRNG_HASH_WORD_COUNT )
		{
			ctx -> HashPos = 0;
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

#endif // PRVRNG_INCLUDED1

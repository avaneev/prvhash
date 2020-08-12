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
 * @version 2.0
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

	uint64_t Hash; ///< Current hash value.
	uint64_t lcg; ///< Current lcg value.
	uint64_t Seed; ///< Current Seed value.
	int EntCtr; ///< Bytes remaining before entropy is injected.
	int HashLeft; ///< Bytes left in hash.
	uint64_t LastHash; ///< Previous generated hash.
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
 * Internal function, calculates "prvhash42" round.
 *
 * @param ctx Pointer to the context structure.
 * @param msg 8-bit entropy message.
 */

inline void prvrng_prvhash42( PRVRNG_CTX* const ctx, const uint64_t msg )
{
	ctx -> Seed ^= msg;

	ctx -> Seed *= ctx -> lcg;
	const uint64_t ph = ctx -> Hash;
	ctx -> Hash ^= ctx -> Seed >> 32;
	ctx -> Seed ^= ph ^ msg;

	ctx -> lcg += ctx -> Seed;
}

/**
 * Function generates the next random 8-bit number.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen( PRVRNG_CTX* const ctx )
{
	if( ctx -> HashLeft == 0 )
	{
		uint64_t msg;

		if( ctx -> EntCtr == 0 )
		{
			ctx -> EntCtr = ( (int) prvrng_gen_entropy( ctx ) + 1 ) << 2;
			msg = prvrng_gen_entropy( ctx );
		}
		else
		{
			msg = 0;
		}

		prvrng_prvhash42( ctx, msg );

		ctx -> HashLeft = 4;
		ctx -> LastHash = ctx -> Hash;
		ctx -> EntCtr--;
	}

	const uint8_t r = (uint8_t) ctx -> LastHash;
	ctx -> LastHash >>= 8;
	ctx -> HashLeft--;

	return( r );
}

/**
 * Function initalizes the entropy PRNG context. It also seeds the generator
 * with initial entropy.
 *
 * @param ctx Pointer to the context structure.
 * @return 0 if failed.
 */

inline int prvrng_init( PRVRNG_CTX* const ctx )
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

	ctx -> Hash = 0;
	ctx -> lcg = 15267459991392010589ULL;
	ctx -> Seed = 7928988912013905173ULL;
	ctx -> EntCtr = 0;
	ctx -> HashLeft = 0;
	ctx -> LastHash = 0;

	int i;

	for( i = 0; i < 32; i++ )
	{
		prvrng_prvhash42( ctx, prvrng_gen_entropy( ctx ));
	}

	return( 1 );
}

/**
 * Function deinitializes the PRNG.
 *
 * @param ctx Pointer to the context structure.
 */

inline void prvrng_final( PRVRNG_CTX* ctx )
{
	#if defined( PRVRNG_UNIX )

		fclose( ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptReleaseContext( ctx -> prov, 0 );

	#endif // defined( PRVRNG_UNIX )
}

/**
 * A test function for "prvrng". Prints 16 random bytes.
 */

inline void prvrng_test()
{
	PRVRNG_CTX ctx;

	if( !prvrng_init( &ctx ))
	{
		return;
	}

	int i;

	for( i = 0; i < 16; i++ )
	{
		printf( "%i\n", (int) prvrng_gen( &ctx ));
	}

	prvrng_final( &ctx );
}

#endif // PRVRNG_INCLUDED

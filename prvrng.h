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
 * @version 2.18
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
 * This function calculates bit count of a 64-bit number, in a platform
 * independent way, can be replaced by an intrinsic.
 *
 * @param v0 Value.
 */

inline int prvrng_popcnt_u64( uint64_t v0 )
{
	int r = 0;
	int i;

	for( i = 0; i < 4; i++ )
	{
		r += prvrng_popcnt_u16( (uint16_t) v0 );
		v0 >>= 16;
	}

	return( r );
}

/**
 * Function generates an 64-bit entropy value and assures this value has
 * between 29 and 35 bits set. This function is required to generate a stable
 * initial state of the hash function. This constraint is usually fulfilled in
 * 1-3 iterations, but in rare cases may require even 10 iterations.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint64_t prvrng_gen_entropy64c( PRVRNG_CTX* const ctx )
{
	while( true )
	{
		uint64_t tv = 0;
		int i;

		for( i = 0; i < 8; i++ )
		{
			tv <<= 8;
			tv += prvrng_gen_entropy( ctx );
		}

		const int bcnt = prvrng_popcnt_u64( tv );

		if( bcnt >= 29 && bcnt <= 35 )
		{
			return( tv );
		}
	}
}

/**
 * Function generates an 64-bit entropy value and assures this value is
 * composed of four 16-bit values that each have 5 to 11 bits set. This
 * function is required to generate a stable initial state of the hash
 * function. This constraint is usually quickly satisfied.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint64_t prvrng_gen_entropy64c16( PRVRNG_CTX* const ctx )
{
	uint64_t val = 0;
	int j;

	for( j = 0; j < 4; j++ )
	{
		while( true )
		{
			uint16_t tv = prvrng_gen_entropy( ctx );
			tv <<= 8;
			tv |= (uint16_t) prvrng_gen_entropy( ctx );

			const int bcnt = prvrng_popcnt_u16( tv );

			if( bcnt >= 5 && bcnt <= 11 )
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
 * Internal function, calculates "prvhash42" round, for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 * @param msgw Entropy message word.
 */

inline void prvrng_prvhash42_32( PRVRNG_CTX* const ctx, const uint64_t msgw )
{
	ctx -> Seed *= ctx -> lcg;
	ctx -> Hash ^= ctx -> Seed >> 32;
	ctx -> Seed ^= (uint32_t) ctx -> Hash ^ msgw;
	ctx -> lcg += ctx -> Seed;
}

/**
 * Function generates the next random 8-bit number, for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen32( PRVRNG_CTX* const ctx )
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

		prvrng_prvhash42_32( ctx, msgw );

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
 * Internal function, calculates "prvhash42" round, for 64-bit hash.
 *
 * @param ctx Pointer to the context structure.
 * @param msgw Entropy message word. Second message byte is assumed to be 0.
 */

inline void prvrng_prvhash42_64( PRVRNG_CTX* const ctx, const uint64_t msgw )
{
	// Lower 32 bits of hash value.

	ctx -> Seed *= ctx -> lcg;
	ctx -> Hash ^= ctx -> Seed >> 32;
	ctx -> Seed ^= (uint32_t) ctx -> Hash ^ msgw;
	ctx -> lcg += ctx -> Seed;

	// Upper 32 bits of hash value.

	ctx -> Seed *= ctx -> lcg;
	ctx -> Hash ^= ctx -> Seed & 0xFFFFFFFF00000000ULL;
	ctx -> Seed ^= ( ctx -> Hash >> 32 ) ^ 0;
	ctx -> lcg += ctx -> Seed;
}

/**
 * Function generates the next random 8-bit number, for 64-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline uint8_t prvrng_gen64( PRVRNG_CTX* const ctx )
{
	if( ctx -> HashLeft == 0 )
	{
		uint64_t msgw;

		if( ctx -> EntCtr == 0 )
		{
			ctx -> EntCtr = ( (int) prvrng_gen_entropy( ctx ) + 1 ) << 3;
			msgw = prvrng_gen_entropy( ctx );
		}
		else
		{
			msgw = 0;
		}

		prvrng_prvhash42_64( ctx, msgw );

		ctx -> HashLeft = 8;
		ctx -> LastHash = ctx -> Hash;
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

inline int prvrng_init32( PRVRNG_CTX* const ctx )
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

	ctx -> Hash = prvrng_gen_entropy64c16( ctx );
	ctx -> lcg = prvrng_gen_entropy64c16( ctx );
	ctx -> Seed = prvrng_gen_entropy64c16( ctx );
	ctx -> EntCtr = 0;
	ctx -> HashLeft = 0;
	ctx -> LastHash = 0;

	return( 1 );
}

/**
 * Function initalizes the entropy PRNG context, for 64-bit hash. It also
 * seeds the generator with initial entropy.
 *
 * @param ctx Pointer to the context structure.
 * @param DoPreInit Pre-initialize the PRNG with the entropy source.
 * @return 0 if failed.
 */

inline int prvrng_init64( PRVRNG_CTX* const ctx )
{
	return( prvrng_init32( ctx ));
}

/**
 * Function deinitializes the PRNG, for 32-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline void prvrng_final32( PRVRNG_CTX* ctx )
{
	#if defined( PRVRNG_UNIX )

		fclose( ctx -> f );

	#else // defined( PRVRNG_UNIX )

		CryptReleaseContext( ctx -> prov, 0 );

	#endif // defined( PRVRNG_UNIX )
}

/**
 * Function deinitializes the PRNG, for 64-bit hash.
 *
 * @param ctx Pointer to the context structure.
 */

inline void prvrng_final64( PRVRNG_CTX* ctx )
{
	prvrng_final32( ctx );
}

/**
 * A test function for "prvrng", 32-bit hash-based. Prints 16 random bytes.
 */

inline void prvrng_test32()
{
	PRVRNG_CTX ctx;

	if( !prvrng_init32( &ctx ))
	{
		printf( "Cannot obtain the entropy source!\n" );
		return;
	}

	int i;

	for( i = 0; i < 16; i++ )
	{
		printf( "%i\n", (int) prvrng_gen32( &ctx ));
	}

	prvrng_final32( &ctx );
}

/**
 * A test function for "prvrng", 64-bit hash-based. Prints 16 random bytes.
 */

inline void prvrng_test64()
{
	PRVRNG_CTX ctx;

	if( !prvrng_init64( &ctx ))
	{
		printf( "Cannot obtain the entropy source!\n" );
		return;
	}

	int i;

	for( i = 0; i < 16; i++ )
	{
		printf( "%i\n", (int) prvrng_gen64( &ctx ));
	}

	prvrng_final64( &ctx );
}

#endif // PRVRNG_INCLUDED

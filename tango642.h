/**
 * tango642.h version 4.3.3
 *
 * The inclusion file for the "tango642" PRVHASH PRNG-based streamed XOR
 * function.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020-2022 Aleksey Vaneev
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

#ifndef TANGO642_INCLUDED
#define TANGO642_INCLUDED

#include "prvhash_core.h"

#define TANGO642_T uint64_t // PRVHASH state variable type.
#define TANGO642_S sizeof( TANGO642_T ) // State variable type's size.
#define TANGO642_S_2 ( TANGO642_S * 2 )
#define TANGO642_HASH_COUNT 16 // Hashwords in keyed PRNG (power-of-2).
#define TANGO642_HASH_SIZE ( TANGO642_HASH_COUNT * TANGO642_S )
#define TANGO642_HASH_MASK ( TANGO642_HASH_SIZE - 1 )
#define TANGO642_FUSE 3 // Firewalling "fused PRNG" size.
#define TANGO642_FN prvhash_core64 // PRVHASH core function name.
#define TANGO642_LUEC prvhash_lu64ec // Unsigned value EC load function.
#define TANGO642_EC PRVHASH_EC64 // Value EC function.
#define TANGO642_SH4( v1, v2, v3, v4 ) \
	{ TANGO642_T t = v1; v1 = v2; v2 = v3; v3 = v4; v4 = t; } // 4-value shift macro.

// Likelihood macros that are used for manually-guided micro-optimization.

#if defined( __GNUC__ ) || defined( __clang__ )

	#define TANGO642_LIKELY( x )  __builtin_expect( x, 1 )

#else // likelihood macros

	#define TANGO642_LIKELY( x ) ( x )

#endif // likelihood macros

/**
 * tango642 context structure, can be placed on stack. On systems where this
 * is relevant, the structure should be aligned to TANGO642_S bytes.
 */

typedef struct
{
	TANGO642_T Seed; ///< Keyed PRNG Seed value.
	TANGO642_T lcg; ///< Keyed PRNG lcg value.
	TANGO642_T Hash[ TANGO642_HASH_COUNT ]; ///< Keyed PRNG hash values.
	TANGO642_T SeedF[ TANGO642_FUSE ]; ///< Firewalling PRNG Seed values.
	TANGO642_T lcgF[ TANGO642_FUSE ]; ///< Firewalling PRNG lcg values.
	TANGO642_T HashF[ TANGO642_FUSE + 1 ]; ///< Firewalling PRNG Hash values.
	TANGO642_T RndBytes[ TANGO642_FUSE ]; ///< The left-over random output.
	size_t RndLeft[ TANGO642_FUSE ]; ///< The number of bytes left in RndBytes.
	size_t HashPos; ///< Keyed PRNG hash array position, in bytes.
} TANGO642_CTX;

/**
 * This function initializes the "tango642" structure. After the session, the
 * tango642_final() function should be called.
 *
 * Note that this function can be also used as a "conditioning" function for
 * the specified "key" and "iv" values, to minimize overhead if "iv" values
 * are pre-generated and cached. In this case, the initialized context
 * structure can be stored as a whole, and used as a substitute for key+iv
 * pair.
 *
 * When "keylen+ivlen" is larger than 1168 bits, there can be theoretical
 * "key+iv" collisions: such collisions should not pose a security threat
 * (negligible probability), but may be perceived as "non-ideal". However,
 * when the "keylen" is 1024 bits long it still allows "iv" to be 128 bits
 * long "safely".
 *
 * @param[out] ctx Pointer to the context structure. Should be aligned to
 * 8 bytes.
 * @param key0 Uniformly-random key buffer, address alignment is unimportant.
 * @param keylen Length of "key", in bytes; should be >= 16, in increments of
 * 8. Should not exceed 128 bytes.
 * @param iv0 Uniformly-random "unsecure" initialization vector (nonce),
 * address alignment is unimportant. Can be 0 if "ivlen" is also 0.
 * @param ivlen Length of "iv", in bytes, in increments of 8; can be zero.
 * Should not exceed 56 bytes.
 */

static inline void tango642_init( TANGO642_CTX* const ctx,
	const void* const key0, const size_t keylen, const void* const iv0,
	const size_t ivlen )
{
	const uint8_t* const key = (const uint8_t*) key0;
	const uint8_t* const iv = (const uint8_t*) iv0;

	memset( ctx, 0, sizeof( TANGO642_CTX ));

	ctx -> Seed = TANGO642_LUEC( key );
	ctx -> SeedF[ 0 ] = TANGO642_LUEC( key + TANGO642_S );

	uint8_t* const ha = (uint8_t*) ctx -> Hash;
	uint8_t* ha2 = ha - TANGO642_S_2;
	size_t i;

	for( i = TANGO642_S_2; i < keylen; i += TANGO642_S )
	{
		*(TANGO642_T*) ( ha2 + i ) = TANGO642_LUEC( key + i );
	}

	TANGO642_T Seed = ctx -> Seed;
	TANGO642_T lcg = ctx -> lcg;

	for( i = 0; i < PRVHASH_INIT_COUNT; i++ )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha );
	}

	ha2 = ha;

	for( i = 0; i < ivlen; i += TANGO642_S )
	{
		const TANGO642_T v = TANGO642_LUEC( iv + i );

		Seed ^= v;
		lcg ^= v;

		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha2 );
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha2 + TANGO642_S ));

		ha2 += TANGO642_S_2;
	}

	for( i = i * 2; i < TANGO642_HASH_SIZE; i += TANGO642_S )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + i ));
	}

	TANGO642_T SeedF1 = ctx -> SeedF[ 0 ];
	TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
	TANGO642_T SeedF3 = ctx -> SeedF[ 2 ];
	TANGO642_T lcgF1 = ctx -> lcgF[ 0 ];
	TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
	TANGO642_T lcgF3 = ctx -> lcgF[ 2 ];
	TANGO642_T HashF1 = ctx -> HashF[ 0 ];
	TANGO642_T HashF2 = ctx -> HashF[ 1 ];
	TANGO642_T HashF3 = ctx -> HashF[ 2 ];
	TANGO642_T HashF4 = ctx -> HashF[ 3 ];

	size_t hp = 0;

	for( i = 0; i < TANGO642_HASH_SIZE; i += TANGO642_S )
	{
		SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
		hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

		SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
		hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

		TANGO642_FN( &SeedF1, &lcgF1, &HashF1 );
		TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
		TANGO642_FN( &SeedF3, &lcgF3, &HashF3 );

		TANGO642_SH4( HashF1, HashF2, HashF3, HashF4 );
	}

	ctx -> Seed = Seed;
	ctx -> lcg = lcg;
	ctx -> SeedF[ 0 ] = SeedF1;
	ctx -> SeedF[ 1 ] = SeedF2;
	ctx -> SeedF[ 2 ] = SeedF3;
	ctx -> lcgF[ 0 ] = lcgF1;
	ctx -> lcgF[ 1 ] = lcgF2;
	ctx -> lcgF[ 2 ] = lcgF3;
	ctx -> HashF[ 0 ] = HashF1;
	ctx -> HashF[ 1 ] = HashF2;
	ctx -> HashF[ 2 ] = HashF3;
	ctx -> HashF[ 3 ] = HashF4;
	ctx -> HashPos = hp;
}

/**
 * This function applies XOR operation over the specified "message" buffer.
 * Prior to using this function, the tango642_init() function should be
 * called.
 *
 * @param[in,out] ctx Pointer to the context structure.
 * @param[in,out] msg0 Message buffer, address alignment is unimportant.
 * @param msglen Message length, in bytes.
 */

static inline void tango642_xor( TANGO642_CTX* const ctx, void* const msg0,
	size_t msglen )
{
	uint8_t* msg = (uint8_t*) msg0;

	while( TANGO642_LIKELY( msglen != 0 ))
	{
		if( ctx -> RndLeft[ TANGO642_FUSE - 1 ] == 0 )
		{
			TANGO642_T Seed = ctx -> Seed;
			TANGO642_T lcg = ctx -> lcg;
			TANGO642_T SeedF1 = ctx -> SeedF[ 0 ];
			TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
			TANGO642_T SeedF3 = ctx -> SeedF[ 2 ];
			TANGO642_T lcgF1 = ctx -> lcgF[ 0 ];
			TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
			TANGO642_T lcgF3 = ctx -> lcgF[ 2 ];
			TANGO642_T HashF1 = ctx -> HashF[ 0 ];
			TANGO642_T HashF2 = ctx -> HashF[ 1 ];
			TANGO642_T HashF3 = ctx -> HashF[ 2 ];
			TANGO642_T HashF4 = ctx -> HashF[ 3 ];
			uint8_t* const ha = (uint8_t*) ctx -> Hash;
			size_t hp = ctx -> HashPos;

			while( TANGO642_LIKELY( msglen > TANGO642_S * TANGO642_FUSE ))
			{
				SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
				hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

				SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
				hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

				TANGO642_T mx1, mx2, mx3;
				memcpy( &mx1, msg, TANGO642_S );
				memcpy( &mx2, msg + TANGO642_S, TANGO642_S );
				memcpy( &mx3, msg + TANGO642_S_2, TANGO642_S );

				mx1 ^= TANGO642_EC( TANGO642_FN( &SeedF1, &lcgF1, &HashF1 ));
				memcpy( msg, &mx1, TANGO642_S );
				msg += TANGO642_S;

				mx2 ^= TANGO642_EC( TANGO642_FN( &SeedF2, &lcgF2, &HashF2 ));
				memcpy( msg, &mx2, TANGO642_S );
				msg += TANGO642_S;

				mx3 ^= TANGO642_EC( TANGO642_FN( &SeedF3, &lcgF3, &HashF3 ));
				memcpy( msg, &mx3, TANGO642_S );
				msg += TANGO642_S;

				TANGO642_SH4( HashF1, HashF2, HashF3, HashF4 );

				msglen -= TANGO642_S * TANGO642_FUSE;
			}

			SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
			hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

			SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
			hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

			ctx -> RndBytes[ 0 ] = TANGO642_FN( &SeedF1, &lcgF1, &HashF1 );
			ctx -> RndBytes[ 1 ] = TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
			ctx -> RndBytes[ 2 ] = TANGO642_FN( &SeedF3, &lcgF3, &HashF3 );

			ctx -> RndLeft[ 0 ] = TANGO642_S;
			ctx -> RndLeft[ 1 ] = TANGO642_S;
			ctx -> RndLeft[ 2 ] = TANGO642_S;

			TANGO642_SH4( HashF1, HashF2, HashF3, HashF4 );

			ctx -> Seed = Seed;
			ctx -> lcg = lcg;
			ctx -> SeedF[ 0 ] = SeedF1;
			ctx -> SeedF[ 1 ] = SeedF2;
			ctx -> SeedF[ 2 ] = SeedF3;
			ctx -> lcgF[ 0 ] = lcgF1;
			ctx -> lcgF[ 1 ] = lcgF2;
			ctx -> lcgF[ 2 ] = lcgF3;
			ctx -> HashF[ 0 ] = HashF1;
			ctx -> HashF[ 1 ] = HashF2;
			ctx -> HashF[ 2 ] = HashF3;
			ctx -> HashF[ 3 ] = HashF4;
			ctx -> HashPos = hp;
		}

		size_t c = ( msglen > ctx -> RndLeft[ 0 ] ?
			ctx -> RndLeft[ 0 ] : msglen );

		if( c != 0 )
		{
			msglen -= c;
			ctx -> RndLeft[ 0 ] -= c;
			TANGO642_T RndBytes = ctx -> RndBytes[ 0 ];

			do
			{
				*msg ^= (uint8_t) RndBytes;
				msg++;
				RndBytes >>= 8;
			} while( --c != 0 );

			ctx -> RndBytes[ 0 ] = RndBytes;
		}

		c = ( msglen > ctx -> RndLeft[ 1 ] ? ctx -> RndLeft[ 1 ] : msglen );

		if( c != 0 )
		{
			msglen -= c;
			ctx -> RndLeft[ 1 ] -= c;
			TANGO642_T RndBytes = ctx -> RndBytes[ 1 ];

			do
			{
				*msg ^= (uint8_t) RndBytes;
				msg++;
				RndBytes >>= 8;
			} while( --c != 0 );

			ctx -> RndBytes[ 1 ] = RndBytes;
		}

		c = ( msglen > ctx -> RndLeft[ 2 ] ? ctx -> RndLeft[ 2 ] : msglen );

		if( c != 0 )
		{
			msglen -= c;
			ctx -> RndLeft[ 2 ] -= c;
			TANGO642_T RndBytes = ctx -> RndBytes[ 2 ];

			do
			{
				*msg ^= (uint8_t) RndBytes;
				msg++;
				RndBytes >>= 8;
			} while( --c != 0 );

			ctx -> RndBytes[ 2 ] = RndBytes;
		}
	}
}

/**
 * Function finalizes the XOR session.
 *
 * @param[in,out] ctx Pointer to the context structure.
 */

static inline void tango642_final( TANGO642_CTX* const ctx )
{
	memset( ctx, 0, sizeof( TANGO642_CTX ));
}

/**
 * This is a "fun concept" XOR session finalization function, to better stand
 * yet unknown quantum-temporal-level malevolent ET challenges (then,
 * increasing TANGO642_HASH_COUNT to some more serious numbers would be
 * necessary).
 *
 * @param[in,out] ctx Pointer to the context structure.
 */

static inline void tango642_final_selfdestruct( TANGO642_CTX* const ctx )
{
	TANGO642_CTX pad;
	const size_t c = sizeof( TANGO642_CTX );

	memset( &pad, 0, c );
	tango642_xor( ctx, &pad, c );

	memcpy( ctx, &pad, c );

	// Now needs an immediate processor's cache system sync with the main
	// memory. Trouble if unpadded *ctx's traces remained in cache, on any
	// core.

	memset( ctx, 0, c );
	memset( &pad, 0, c );
}

#endif // TANGO642_INCLUDED

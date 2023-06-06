/**
 * tango642.h version 4.3.9
 *
 * The inclusion file for the "tango642" PRVHASH PRNG-based streamed XOR
 * function.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2020-2023 Aleksey Vaneev
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
#define TANGO642_PAR 4 // Firewalling "parallel PRNG" size.
#define TANGO642_FN prvhash_core64 // PRVHASH core function name.
#define TANGO642_LUEC prvhash_lu64ec // Unsigned value EC load function.
#define TANGO642_EC PRVHASH_EC64 // Value EC function.
#define TANGO642_SH( v1, v2, v3, v4, v5 ) \
	{ TANGO642_T t = v1; v1 = v2; v2 = v3; v3 = v4; v4 = v5; v5 = t; }
	// 5-value shift macro.

/**
 * tango642 context structure, can be placed on stack. On systems where this
 * is relevant, the structure should be aligned to TANGO642_S bytes.
 */

typedef struct
{
	TANGO642_T Seed; ///< Keyed PRNG Seed value.
	TANGO642_T lcg; ///< Keyed PRNG lcg value.
	TANGO642_T Hash[ TANGO642_HASH_COUNT ]; ///< Keyed PRNG hash values.
	TANGO642_T SeedF[ TANGO642_PAR ]; ///< Firewalling PRNG Seed values.
	TANGO642_T lcgF[ TANGO642_PAR ]; ///< Firewalling PRNG lcg values.
	TANGO642_T HashF[ TANGO642_PAR + 1 ]; ///< Firewalling PRNG hash values.
	TANGO642_T RndBytes[ TANGO642_PAR ]; ///< The leftover random output.
	size_t RndLeft[ TANGO642_PAR ]; ///< The number of bytes left in RndBytes.
	size_t RndPos; ///< Position within the RndLeft array.
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
 * When "keylen+ivlen" is larger than 1104 bits, there can be theoretical
 * "key+iv" collisions: such collisions should not pose a security threat
 * (negligible probability), but may be perceived as "non-ideal". However,
 * when the "keylen" is 1024 bits long it still allows "iv" to be 64 bits
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
 * Should not exceed 64 bytes.
 */

static inline void tango642_init( TANGO642_CTX* const ctx,
	const void* const key0, const size_t keylen, const void* const iv0,
	const size_t ivlen )
{
	const uint8_t* const key = (const uint8_t*) key0;
	const uint8_t* const iv = (const uint8_t*) iv0;

	memset( ctx, 0, sizeof( TANGO642_CTX ));

	// Load a key.

	TANGO642_T Seed = TANGO642_LUEC( key );
	TANGO642_T lcg = 0;

	uint8_t* const ha = (uint8_t*) ctx -> Hash;
	uint8_t* ha2 = ha - TANGO642_S;
	size_t i;

	for( i = TANGO642_S; i < keylen; i += TANGO642_S )
	{
		*(TANGO642_T*) ( ha2 + i ) = TANGO642_LUEC( key + i );
	}

	// Initialize keyed PRNG.

	for( i = 0; i < PRVHASH_INIT_COUNT; i++ )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha );
	}

	// Input "iv" as external unstructured entropy.

	ha2 = ha;

	for( i = 0; i < ivlen; i += TANGO642_S )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha2 );

		const TANGO642_T v = TANGO642_LUEC( iv + i );

		Seed ^= v;
		lcg ^= v;

		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha2 + TANGO642_S ));

		ha2 += TANGO642_S_2;
	}

	for( i = i * 2; i < TANGO642_HASH_SIZE; i += TANGO642_S )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + i ));
	}

	// Eliminate traces of input entropy, like it is done in hashing.

	for( i = 0; i < TANGO642_HASH_SIZE; i += TANGO642_S )
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + i ));
	}

	TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha );

	// Initialize firewalling PRNG, making sure each lcg and hash value
	// receives keyed entropy thrice, or otherwise a further keyed entropy
	// input helps to reveal the key. Such entropy accumulation is the essence
	// of "firewalling".

	TANGO642_T SeedF1 = ctx -> SeedF[ 0 ];
	TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
	TANGO642_T SeedF3 = ctx -> SeedF[ 2 ];
	TANGO642_T SeedF4 = ctx -> SeedF[ 3 ];
	TANGO642_T lcgF1 = ctx -> lcgF[ 0 ];
	TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
	TANGO642_T lcgF3 = ctx -> lcgF[ 2 ];
	TANGO642_T lcgF4 = ctx -> lcgF[ 3 ];
	TANGO642_T HashF1 = ctx -> HashF[ 0 ];
	TANGO642_T HashF2 = ctx -> HashF[ 1 ];
	TANGO642_T HashF3 = ctx -> HashF[ 2 ];
	TANGO642_T HashF4 = ctx -> HashF[ 3 ];
	TANGO642_T HashF5 = ctx -> HashF[ 4 ];

	size_t hp = TANGO642_S;

	for( i = 0; i < ( TANGO642_PAR + 1 ) * 3; i++ )
	{
		// Input from keyed PRNG extends PRNG period's exponent of the output.

		SeedF4 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
		hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

		// Parallel arrangement PRNG for efficiency.

		TANGO642_FN( &SeedF1, &lcgF1, &HashF1 );
		TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
		TANGO642_FN( &SeedF3, &lcgF3, &HashF3 );
		TANGO642_FN( &SeedF4, &lcgF4, &HashF4 );

		TANGO642_SH( HashF1, HashF2, HashF3, HashF4, HashF5 );
	}

	ctx -> Seed = Seed;
	ctx -> lcg = lcg;
	ctx -> SeedF[ 0 ] = SeedF1;
	ctx -> SeedF[ 1 ] = SeedF2;
	ctx -> SeedF[ 2 ] = SeedF3;
	ctx -> SeedF[ 3 ] = SeedF4;
	ctx -> lcgF[ 0 ] = lcgF1;
	ctx -> lcgF[ 1 ] = lcgF2;
	ctx -> lcgF[ 2 ] = lcgF3;
	ctx -> lcgF[ 3 ] = lcgF4;
	ctx -> HashF[ 0 ] = HashF1;
	ctx -> HashF[ 1 ] = HashF2;
	ctx -> HashF[ 2 ] = HashF3;
	ctx -> HashF[ 3 ] = HashF4;
	ctx -> HashF[ 4 ] = HashF5;
	ctx -> HashPos = hp;
	ctx -> RndPos = TANGO642_PAR;
}

/**
 * This function applies XOR operation over the specified "message" buffer.
 * Prior to using this function, the tango642_init() function should be
 * called.
 *
 * @param[in,out] ctx Pointer to the context structure.
 * @param[in,out] msg0 Message buffer, address alignment is unimportant,
 * can be zero if msglen is zero.
 * @param msglen Message length, in bytes, can be zero.
 */

static inline void tango642_xor( TANGO642_CTX* const ctx, void* const msg0,
	size_t msglen )
{
	uint8_t* msg = (uint8_t*) msg0;

	while( 1 )
	{
		if( ctx -> RndPos == TANGO642_PAR )
		{
			TANGO642_T Seed = ctx -> Seed;
			TANGO642_T lcg = ctx -> lcg;
			TANGO642_T SeedF1 = ctx -> SeedF[ 0 ];
			TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
			TANGO642_T SeedF3 = ctx -> SeedF[ 2 ];
			TANGO642_T SeedF4 = ctx -> SeedF[ 3 ];
			TANGO642_T lcgF1 = ctx -> lcgF[ 0 ];
			TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
			TANGO642_T lcgF3 = ctx -> lcgF[ 2 ];
			TANGO642_T lcgF4 = ctx -> lcgF[ 3 ];
			TANGO642_T HashF1 = ctx -> HashF[ 0 ];
			TANGO642_T HashF2 = ctx -> HashF[ 1 ];
			TANGO642_T HashF3 = ctx -> HashF[ 2 ];
			TANGO642_T HashF4 = ctx -> HashF[ 3 ];
			TANGO642_T HashF5 = ctx -> HashF[ 4 ];
			uint8_t* const ha = (uint8_t*) ctx -> Hash;
			size_t hp = ctx -> HashPos;

			while( msglen >= TANGO642_S * TANGO642_PAR )
			{
				SeedF4 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
				hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

				TANGO642_T mx1, mx2;
				memcpy( &mx1, msg, TANGO642_S );
				memcpy( &mx2, msg + TANGO642_S, TANGO642_S );

				mx1 ^= TANGO642_EC( TANGO642_FN( &SeedF1, &lcgF1, &HashF1 ));
				memcpy( msg, &mx1, TANGO642_S );
				msg += TANGO642_S;

				mx2 ^= TANGO642_EC( TANGO642_FN( &SeedF2, &lcgF2, &HashF2 ));
				memcpy( msg, &mx2, TANGO642_S );
				msg += TANGO642_S;

				TANGO642_T mx3, mx4;
				memcpy( &mx3, msg, TANGO642_S );
				memcpy( &mx4, msg + TANGO642_S, TANGO642_S );

				mx3 ^= TANGO642_EC( TANGO642_FN( &SeedF3, &lcgF3, &HashF3 ));
				memcpy( msg, &mx3, TANGO642_S );
				msg += TANGO642_S;

				mx4 ^= TANGO642_EC( TANGO642_FN( &SeedF4, &lcgF4, &HashF4 ));
				memcpy( msg, &mx4, TANGO642_S );
				msg += TANGO642_S;

				TANGO642_SH( HashF1, HashF2, HashF3, HashF4, HashF5 );

				msglen -= TANGO642_S * TANGO642_PAR;
			}

			SeedF4 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + hp ));
			hp = ( hp + TANGO642_S ) & TANGO642_HASH_MASK;

			ctx -> RndBytes[ 0 ] = TANGO642_FN( &SeedF1, &lcgF1, &HashF1 );
			ctx -> RndBytes[ 1 ] = TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
			ctx -> RndBytes[ 2 ] = TANGO642_FN( &SeedF3, &lcgF3, &HashF3 );
			ctx -> RndBytes[ 3 ] = TANGO642_FN( &SeedF4, &lcgF4, &HashF4 );

			ctx -> RndLeft[ 0 ] = TANGO642_S;
			ctx -> RndLeft[ 1 ] = TANGO642_S;
			ctx -> RndLeft[ 2 ] = TANGO642_S;
			ctx -> RndLeft[ 3 ] = TANGO642_S;
			ctx -> RndPos = 0;

			ctx -> Seed = Seed;
			ctx -> lcg = lcg;
			ctx -> SeedF[ 0 ] = SeedF1;
			ctx -> SeedF[ 1 ] = SeedF2;
			ctx -> SeedF[ 2 ] = SeedF3;
			ctx -> SeedF[ 3 ] = SeedF4;
			ctx -> lcgF[ 0 ] = lcgF1;
			ctx -> lcgF[ 1 ] = lcgF2;
			ctx -> lcgF[ 2 ] = lcgF3;
			ctx -> lcgF[ 3 ] = lcgF4;
			ctx -> HashF[ 0 ] = HashF2; // Store shifted.
			ctx -> HashF[ 1 ] = HashF3;
			ctx -> HashF[ 2 ] = HashF4;
			ctx -> HashF[ 3 ] = HashF5;
			ctx -> HashF[ 4 ] = HashF1;
			ctx -> HashPos = hp;
		}

		size_t p = ctx -> RndPos;

		while( 1 )
		{
			size_t rl = ctx -> RndLeft[ p ];

			if( msglen < rl )
			{
				if( msglen != 0 )
				{
					TANGO642_T RndBytes = ctx -> RndBytes[ p ];
					ctx -> RndLeft[ p ] = rl - msglen;

					do
					{
						*msg ^= (uint8_t) RndBytes;
						RndBytes >>= 8;
						msg++;
					} while( --msglen != 0 );

					ctx -> RndBytes[ p ] = RndBytes;
				}

				ctx -> RndPos = p;
				return;
			}

			TANGO642_T RndBytes = ctx -> RndBytes[ p ];
			msglen -= rl;

			do
			{
				*msg ^= (uint8_t) RndBytes;
				RndBytes >>= 8;
				msg++;
			} while( --rl != 0 );

			if( ++p == TANGO642_PAR )
			{
				ctx -> RndPos = p;
				break;
			}
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

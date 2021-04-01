/**
 * tango642.h version 3.3.4
 *
 * The inclusion file for the "tango642" PRVHASH PRNG-based stream cipher.
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

#ifndef TANGO642_INCLUDED
#define TANGO642_INCLUDED

#include "prvhash_aux.h"
#include "prvhash_core.h"

/**
 * Tango642 context structure.
 */

#define TANGO642_HASH_COUNT 16 // Hashwords in a hasharray.
#define TANGO642_T uint64_t // PRVHASH state variable type.
#define TANGO642_FN prvhash_core64 // PRVHASH core function name.
#define TANGO642_LU prvhash_lu64ec // Unsigned value EC load function.
#define TANGO642_EC64 PRVHASH_EC64 // Value EC function.
#define TANGO642_SH3( v1, v2, v3 ) \
	{ TANGO642_T t = v1; v1 = v2; v2 = v3; v3 = t; } // 3-value shift macro.

/**
 * tango642 context structure, can be placed on stack.
 */

typedef struct
{
	TANGO642_T Seed; ///< Current Seed value.
	TANGO642_T lcg; ///< Current lcg value.
	TANGO642_T Hash[ TANGO642_HASH_COUNT ]; ///< Current hash values.
	TANGO642_T SeedF[ 2 ]; ///< "Firewalling" fused PRNG Seed values.
	TANGO642_T lcgF[ 2 ]; ///< "Firewalling" fused PRNG lcg values.
	TANGO642_T HashF[ 3 ]; ///< "Firewalling" fused PRNG Hash values.
	TANGO642_T RndBytes[ 2 ]; ///< The recent partial random outputs.
	size_t RndLeft[ 2 ]; ///< The number of bytes left in RndBytes.
	size_t HashPos; ///< Hash array position, in bytes.
} TANGO642_CTX;

/**
 * This function initializes the "tango642" structure. After the session, the
 * tango642_final() function should be called.
 *
 * Note that this function can be also used as a "conditioning" function for
 * the specified "key" and "iv" values, to minimize overhead if "iv" values
 * are pre-generated and cached. In this case, the initialized context
 * structure can stored as a whole, and used as a substitute for key+iv pair.
 *
 * @param ctx Pointer to the context structure.
 * @param key Uniformly-random key buffer, alignment is unimportant.
 * @param keylen Length of "key" in bytes, should be >= 16, in increments of
 * 8. Should not exceed 128 bytes.
 * @param iv Uniformly-random "unsecure" initialization vector (nonce),
 * alignment is unimportant. Can be 0 if "ivlen" is also 0.
 * @param ivlen Length of "iv" in bytes, in increments of 8, can be zero.
 * Should not exceed 96 bytes.
 */

inline void tango642_init( TANGO642_CTX* ctx, const uint8_t* key,
	size_t keylen, const uint8_t* iv, size_t ivlen )
{
	memset( ctx, 0, sizeof( TANGO642_CTX ));

	ctx -> Seed = TANGO642_LU( key );
	ctx -> SeedF[ 0 ] = TANGO642_LU( key + sizeof( TANGO642_T ));

	key += sizeof( TANGO642_T ) * 2;
	keylen -= sizeof( TANGO642_T ) * 2;

	int i;

	for( i = 0; i < TANGO642_HASH_COUNT; i++ )
	{
		if( keylen == 0 )
		{
			break;
		}

		ctx -> Hash[ i ] = TANGO642_LU( key );
		key += sizeof( TANGO642_T );
		keylen -= sizeof( TANGO642_T );
	}

	TANGO642_T Seed = ctx -> Seed;
	TANGO642_T lcg = ctx -> lcg;
	TANGO642_T SeedF = ctx -> SeedF[ 0 ];
	TANGO642_T lcgF = ctx -> lcgF[ 0 ];
	TANGO642_T HashF = ctx -> HashF[ 0 ];
	TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
	TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
	TANGO642_T HashF2 = ctx -> HashF[ 1 ];
	TANGO642_T HashF3 = ctx -> HashF[ 2 ];
	TANGO642_T* const ha = ctx -> Hash;

	for( i = 0; i < TANGO642_HASH_COUNT; i++ )
	{
		TANGO642_FN( &Seed, &lcg, ha + i );
	}

	const int ivo = TANGO642_HASH_COUNT - 2 -
		(int) ( ivlen / sizeof( TANGO642_T ));

	for( i = 0; i < TANGO642_HASH_COUNT; i++ )
	{
		if( i >= ivo && ivlen > 0 )
		{
			lcg ^= TANGO642_LU( iv );
			iv += sizeof( TANGO642_T );
			ivlen -= sizeof( TANGO642_T );
		}

		TANGO642_FN( &Seed, &lcg, ha + i );
	}

	for( i = 0; i < TANGO642_HASH_COUNT; i++ )
	{
		SeedF2 ^= TANGO642_FN( &Seed, &lcg, ha + i );
		TANGO642_FN( &SeedF, &lcgF, &HashF );
		TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
		TANGO642_SH3( HashF, HashF2, HashF3 );
	}

	ctx -> Seed = Seed;
	ctx -> lcg = lcg;
	ctx -> SeedF[ 0 ] = SeedF;
	ctx -> lcgF[ 0 ] = lcgF;
	ctx -> HashF[ 0 ] = HashF;
	ctx -> SeedF[ 1 ] = SeedF2;
	ctx -> lcgF[ 1 ] = lcgF2;
	ctx -> HashF[ 1 ] = HashF2;
	ctx -> HashF[ 2 ] = HashF3;
}

/**
 * This function applies XOR operation over the specified "message" buffer.
 * Prior to using this function, the tango642_init() function should be
 * called.
 *
 * @param ctx Pointer to the context structure.
 * @param[in,out] msg Message buffer, alignment is unimportant.
 * @param msglen Message length, in bytes.
 */

inline void tango642_xor( TANGO642_CTX* ctx, uint8_t* msg, size_t msglen )
{
	TANGO642_T Seed = ctx -> Seed;
	TANGO642_T lcg = ctx -> lcg;
	TANGO642_T SeedF = ctx -> SeedF[ 0 ];
	TANGO642_T lcgF = ctx -> lcgF[ 0 ];
	TANGO642_T HashF = ctx -> HashF[ 0 ];
	TANGO642_T SeedF2 = ctx -> SeedF[ 1 ];
	TANGO642_T lcgF2 = ctx -> lcgF[ 1 ];
	TANGO642_T HashF2 = ctx -> HashF[ 1 ];
	TANGO642_T HashF3 = ctx -> HashF[ 2 ];
	uint8_t* ha = (uint8_t*) ctx -> Hash + ctx -> HashPos;
	uint8_t* const haend = (uint8_t*) ( ctx -> Hash + TANGO642_HASH_COUNT );

	while( 1 )
	{
		if( ctx -> RndLeft[ 1 ] == 0 )
		{
			size_t rep = msglen >> 4;

			while( rep > 0 )
			{
				SeedF2 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha );

				TANGO642_T mx, mx2;
				memcpy( &mx, msg, sizeof( mx ));
				memcpy( &mx2, msg + sizeof( mx ), sizeof( mx2 ));
				mx ^= TANGO642_EC64( TANGO642_FN( &SeedF, &lcgF, &HashF ));
				mx2 ^= TANGO642_EC64( TANGO642_FN( &SeedF2, &lcgF2, &HashF2 ));
				memcpy( msg, &mx, sizeof( mx ));
				memcpy( msg + sizeof( mx ), &mx2, sizeof( mx2 ));

				TANGO642_SH3( HashF, HashF2, HashF3 );

				ha += sizeof( TANGO642_T );

				if( ha == haend )
				{
					ha -= TANGO642_HASH_COUNT * sizeof( TANGO642_T );
				}

				rep--;
				msg += sizeof( TANGO642_T ) * 2;
			}

			msglen &= 15;

			if( msglen == 0 )
			{
				break;
			}

			SeedF2 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ha );

			ctx -> RndBytes[ 0 ] = TANGO642_EC64(
				TANGO642_FN( &SeedF, &lcgF, &HashF ));

			ctx -> RndBytes[ 1 ] = TANGO642_EC64(
				TANGO642_FN( &SeedF2, &lcgF2, &HashF2 ));

			TANGO642_SH3( HashF, HashF2, HashF3 );

			ha += sizeof( TANGO642_T );

			if( ha == haend )
			{
				ha -= TANGO642_HASH_COUNT * sizeof( TANGO642_T );
			}

			ctx -> RndLeft[ 0 ] = sizeof( TANGO642_T );
			ctx -> RndLeft[ 1 ] = sizeof( TANGO642_T );
		}

		size_t c = ( msglen > ctx -> RndLeft[ 0 ] ?
			ctx -> RndLeft[ 0 ] : msglen );

		if( c > 0 )
		{
			msglen -= c;
			ctx -> RndLeft[ 0 ] -= c;
			TANGO642_T RndBytes = ctx -> RndBytes[ 0 ];

			do
			{
				*msg ^= (uint8_t) RndBytes;
				RndBytes >>= 8;
				msg++;
				c--;
			} while( c > 0 );

			ctx -> RndBytes[ 0 ] = RndBytes;
		}

		c = ( msglen > ctx -> RndLeft[ 1 ] ? ctx -> RndLeft[ 1 ] : msglen );

		if( c == 0 )
		{
			break;
		}

		msglen -= c;
		ctx -> RndLeft[ 1 ] -= c;
		TANGO642_T RndBytes = ctx -> RndBytes[ 1 ];

		do
		{
			*msg ^= (uint8_t) RndBytes;
			RndBytes >>= 8;
			msg++;
			c--;
		} while( c > 0 );

		ctx -> RndBytes[ 1 ] = RndBytes;
	}

	ctx -> Seed = Seed;
	ctx -> lcg = lcg;
	ctx -> SeedF[ 0 ] = SeedF;
	ctx -> lcgF[ 0 ] = lcgF;
	ctx -> HashF[ 0 ] = HashF;
	ctx -> SeedF[ 1 ] = SeedF2;
	ctx -> lcgF[ 1 ] = lcgF2;
	ctx -> HashF[ 1 ] = HashF2;
	ctx -> HashF[ 2 ] = HashF3;
	ctx -> HashPos = ha - (uint8_t*) ctx -> Hash;
}

/**
 * Function finalizes the XOR session.
 *
 * @param ctx Pointer to the context structure.
 */

inline void tango642_final( TANGO642_CTX* ctx )
{
	memset( ctx, 0, sizeof( TANGO642_CTX ));
}

#endif // TANGO642_INCLUDED

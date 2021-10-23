/**
 * tango642.h version 4.0.3
 *
 * The inclusion file for the "tango642" PRVHASH PRNG-based streamed XOR
 * function.
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

#include "prvhash_core.h"

#define TANGO642_T uint64_t // PRVHASH state variable type.
#define TANGO642_HASH_COUNT 16 // Hashwords in keyed PRNG's hasharray.
#define TANGO642_HASH_SIZE ( TANGO642_HASH_COUNT * sizeof( TANGO642_T ))
#define TANGO642_HASH_MASK ( TANGO642_HASH_SIZE - 1 )
#define TANGO642_FUSE 3 // Firewalling "fused PRNG" size.
#define TANGO642_FN prvhash_core64 // PRVHASH core function name.
#define TANGO642_LUEC prvhash_lu64ec // Unsigned value EC load function.
#define TANGO642_EC PRVHASH_EC64 // Value EC function.
#define TANGO642_SH4( v1, v2, v3, v4 ) \
	{ TANGO642_T t = v1; v1 = v2; v2 = v3; v3 = v4; v4 = t; } // 4-value shift macro.

/**
 * tango642 context structure, can be placed on stack. On systems where this
 * is relevant, the structure should be aligned to sizeof( TANGO642_T ) bytes.
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
 * "key+iv" collisions: such collisions should not pose a security threat, but
 * may be perceived as "non-ideal". However, when the "keylen" is 1024
 * bits long, this still allows "iv" to be 128 bits long "safely".
 *
 * @param ctx Pointer to the context structure.
 * @param key Uniformly-random key buffer, alignment is unimportant.
 * @param keylen Length of "key" in bytes, should be >= 16, in increments of
 * 8. Should not exceed 128 bytes.
 * @param iv Uniformly-random "unsecure" initialization vector (nonce),
 * alignment is unimportant. Can be 0 if "ivlen" is also 0.
 * @param ivlen Length of "iv" in bytes, in increments of 8, can be zero.
 * Should not exceed 80 bytes.
 */

inline void tango642_init( TANGO642_CTX* ctx, const uint8_t* key,
	size_t keylen, const uint8_t* iv, size_t ivlen )
{
	memset( ctx, 0, sizeof( TANGO642_CTX ));

	ctx -> Seed = TANGO642_LUEC( key );
	key += sizeof( TANGO642_T );

	ctx -> SeedF[ 0 ] = TANGO642_LUEC( key );
	key += sizeof( TANGO642_T );

	keylen -= sizeof( TANGO642_T ) * 2;

	uint8_t* const ha = (uint8_t*) ctx -> Hash;
	size_t i;

	for( i = 0; i < keylen; i += sizeof( TANGO642_T ))
	{
		*(TANGO642_T*) ( ha + i ) = TANGO642_LUEC( key + i );
	}

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

	for( i = 0; i < TANGO642_HASH_SIZE; i += sizeof( TANGO642_T ))
	{
		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + i ));
	}

	const size_t ivo = TANGO642_HASH_SIZE - sizeof( TANGO642_T ) * 4 - ivlen;

	for( i = 0; i < TANGO642_HASH_SIZE; i += sizeof( TANGO642_T ))
	{
		if( i >= ivo && ivlen > 0 )
		{
			lcg ^= TANGO642_LUEC( iv );
			iv += sizeof( TANGO642_T );
			ivlen -= sizeof( TANGO642_T );
		}

		TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + i ));
	}

	size_t HashPos = 0;

	for( i = 0; i < TANGO642_HASH_SIZE; i += sizeof( TANGO642_T ))
	{
		SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + HashPos ));
		HashPos = ( HashPos + sizeof( TANGO642_T )) & TANGO642_HASH_MASK;
		SeedF3 ^= TANGO642_FN( &Seed, &lcg, (TANGO642_T*) ( ha + HashPos ));
		HashPos = ( HashPos + sizeof( TANGO642_T )) & TANGO642_HASH_MASK;

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
	ctx -> HashPos = HashPos;
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
	while( msglen > 0 )
	{
		if( ctx -> RndLeft[ 2 ] == 0 )
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
			size_t HashPos = ctx -> HashPos;

			while( msglen > sizeof( TANGO642_T ) * TANGO642_FUSE )
			{
				SeedF3 ^= TANGO642_FN( &Seed, &lcg,
					(TANGO642_T*) ( ha + HashPos ));

				HashPos = ( HashPos + sizeof( TANGO642_T )) &
					TANGO642_HASH_MASK;

				SeedF3 ^= TANGO642_FN( &Seed, &lcg,
					(TANGO642_T*) ( ha + HashPos ));

				HashPos = ( HashPos + sizeof( TANGO642_T )) &
					TANGO642_HASH_MASK;

				TANGO642_T mx1, mx2, mx3;
				memcpy( &mx1, msg, sizeof( mx1 ));
				memcpy( &mx2, msg + sizeof( mx1 ), sizeof( mx2 ));
				memcpy( &mx3, msg + sizeof( mx1 ) * 2, sizeof( mx3 ));

				mx1 ^= TANGO642_EC( TANGO642_FN( &SeedF1, &lcgF1, &HashF1 ));
				mx2 ^= TANGO642_EC( TANGO642_FN( &SeedF2, &lcgF2, &HashF2 ));
				mx3 ^= TANGO642_EC( TANGO642_FN( &SeedF3, &lcgF3, &HashF3 ));

				memcpy( msg, &mx1, sizeof( mx1 ));
				msg += sizeof( mx1 );
				memcpy( msg, &mx2, sizeof( mx2 ));
				msg += sizeof( mx2 );
				memcpy( msg, &mx3, sizeof( mx3 ));
				msg += sizeof( mx3 );

				TANGO642_SH4( HashF1, HashF2, HashF3, HashF4 );

				msglen -= sizeof( TANGO642_T ) * TANGO642_FUSE;
			}

			SeedF3 ^= TANGO642_FN( &Seed, &lcg,
				(TANGO642_T*) ( ha + HashPos ));

			HashPos = ( HashPos + sizeof( TANGO642_T )) & TANGO642_HASH_MASK;

			SeedF3 ^= TANGO642_FN( &Seed, &lcg,
				(TANGO642_T*) ( ha + HashPos ));

			HashPos = ( HashPos + sizeof( TANGO642_T )) & TANGO642_HASH_MASK;

			ctx -> RndBytes[ 0 ] = TANGO642_FN( &SeedF1, &lcgF1, &HashF1 );
			ctx -> RndBytes[ 1 ] = TANGO642_FN( &SeedF2, &lcgF2, &HashF2 );
			ctx -> RndBytes[ 2 ] = TANGO642_FN( &SeedF3, &lcgF3, &HashF3 );
			ctx -> RndLeft[ 0 ] = sizeof( TANGO642_T );
			ctx -> RndLeft[ 1 ] = sizeof( TANGO642_T );
			ctx -> RndLeft[ 2 ] = sizeof( TANGO642_T );

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
			ctx -> HashPos = HashPos;
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

		if( c > 0 )
		{
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

		c = ( msglen > ctx -> RndLeft[ 2 ] ? ctx -> RndLeft[ 2 ] : msglen );

		if( c > 0 )
		{
			msglen -= c;
			ctx -> RndLeft[ 2 ] -= c;
			TANGO642_T RndBytes = ctx -> RndBytes[ 2 ];

			do
			{
				*msg ^= (uint8_t) RndBytes;
				RndBytes >>= 8;
				msg++;
				c--;
			} while( c > 0 );

			ctx -> RndBytes[ 2 ] = RndBytes;
		}
	}
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

/**
 * This is a "fun concept" XOR session finalization function, to better stand
 * yet unknown quantum-level challenges (then, increasing TANGO642_HASH_COUNT
 * to some more serious numbers would not hurt).
 *
 * @param ctx Pointer to the context structure.
 */

inline void tango642_final_selfdestruct( TANGO642_CTX* ctx )
{
	TANGO642_CTX pad;
	memset( &pad, 0, sizeof( TANGO642_CTX ));
	tango642_xor( ctx, (uint8_t*) &pad, sizeof( TANGO642_CTX ));

	memcpy( ctx, (uint8_t*) &pad, sizeof( TANGO642_CTX ));

	// Needs an immediate processor's cache system sync with the main memory.
	// Trouble if unpadded *ctx's traces remained in cache, on any core.
}

#endif // TANGO642_INCLUDED

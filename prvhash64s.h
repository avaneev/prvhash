/**
 * prvhash64s.h version 3.3
 *
 * The inclusion file for the "prvhash64s" hash function. Efficient on large
 * data blocks, more secure, streamed. Implements a parallel variant of the
 * "prvhash64" hash function.
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

#ifndef PRVHASH64S_INCLUDED
#define PRVHASH64S_INCLUDED

#include "prvhash_core.h"
#include "prvhash_aux.h"

#define PRVHASH64S_PAR 4 // PRVHASH parallelism.
#define PRVHASH64S_LEN 32 // Intermediate block's length, in bytes.

/**
 * The context structure of the "prvhash64s_X" functions.
 */

typedef struct {
	uint64_t Seed[ PRVHASH64S_PAR ]; ///< Current parallel "Seed" values.
	uint64_t lcg[ PRVHASH64S_PAR ]; ///< Current parallel "lcg" values.
	uint8_t Block[ PRVHASH64S_LEN ]; ///< Intermediate input data block.
	size_t BlockFill; ///< The number of bytes filled in the Block.
	uint8_t* Hash; ///< Pointer to the hash buffer.
	size_t HashLen; ///< Hash buffer length, in bytes, >= 8, increments of 8.
	size_t HashPos; ///< Hash buffer position.
	size_t InitBytePos; ///< Initial input byte position, does not accumulate.
	uint8_t IsHashFilled; ///< Flag denoting that the whole hash was filled.
	uint8_t fb; ///< Final stream bit value, for hashing finalization.
} PRVHASH64S_CTX;

/**
 * PRVHASH streaming hash function initialization (64-bit state variables)
 * This function should be called before the hashing session.
 *
 * @param ctx Context structure.
 * @param[in,out] Hash The hash buffer. The length of this buffer should be
 * equal to HashLen. If InitVec is non-NULL, the hash will not be initially
 * reset to the default values, and it should be pre-initialized with
 * uniformly-random bytes (there are no restrictions on which values to use
 * for initialization: even an all-zero value can be used). The provided hash
 * will be automatically endianness-corrected. On systems where this is
 * relevant, this address should be aligned to 64 bits. This pointer will be
 * stored in the "ctx" structure.
 * @param HashLen The required hash length, in bytes, should be >= 8, in
 * increments of 8.
 * @param SeedXOR Optional values, to XOR the default seeds with. To use the
 * default seeds, set to 0. If InitVec is non-NULL, this SeedXOR is ignored
 * and should be set to 0. Otherwise, the SeedXOR values can have any bit
 * length, up to four 64-bit values can be supplied, and are used only as an
 * additional entropy source. They should be endianness-corrected.
 * @param InitVec If non-NULL, an "initialization vector" for internal "Seed"
 * and "lcg" variables. Full 64-byte uniformly-random value should be supplied
 * in this case, preferrably with a good entropy quantity estimate.
 */

inline void prvhash64s_init( PRVHASH64S_CTX* ctx, uint8_t* const Hash,
	const size_t HashLen, const uint64_t SeedXOR[ PRVHASH64S_PAR ],
	const uint8_t InitVec[ PRVHASH64S_PAR * 16 ])
{
	int i;

	if( InitVec == 0 )
	{
		memset( Hash, 0, HashLen );

		if( SeedXOR == 0 )
		{
			for( i = 0; i < PRVHASH64S_PAR; i++ )
			{
				ctx -> Seed[ i ] = 0;
				ctx -> lcg[ i ] = 0;
			}
		}
		else
		{
			for( i = 0; i < PRVHASH64S_PAR; i++ )
			{
				ctx -> Seed[ i ] = SeedXOR[ i ];
				ctx -> lcg[ i ] = 0;
			}
		}
	}
	else
	{
		prvhash_ec64( Hash, HashLen );

		for( i = 0; i < PRVHASH64S_PAR; i++ )
		{
			ctx -> Seed[ i ] = prvhash_lu64ec( InitVec + i * 16 );
			ctx -> lcg[ i ] = prvhash_lu64ec( InitVec + i * 16 + 8 );
		}
	}

	ctx -> BlockFill = 0;
	ctx -> Hash = Hash;
	ctx -> HashLen = HashLen;
	ctx -> HashPos = 0;
	ctx -> InitBytePos = 0;
	ctx -> IsHashFilled = 0;
	ctx -> fb = 1;

	for( i = 0; i < 5; i++ )
	{
		uint64_t* const ph = (uint64_t*) ( ctx -> Hash + ctx -> HashPos );
		int k;

		for( k = 0; k < PRVHASH64S_PAR; k++ )
		{
			prvhash_core64( &ctx -> Seed[ k ], &ctx -> lcg[ k ], ph );
		}

		ctx -> HashPos += sizeof( uint64_t );

		if( ctx -> HashPos == ctx -> HashLen )
		{
			ctx -> HashPos = 0;
		}
	}
}

/**
 * This function updates the hash according to the contents of the message.
 * Before this function can be called, the prvhash64s_init() should be called,
 * to initialize the context structure. When the streamed hashing is finished,
 * the prvhash64s_final() function should be called.
 *
 * @param ctx Context structure.
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 */

inline void prvhash64s_update( PRVHASH64S_CTX* ctx, const uint8_t* Msg,
	size_t MsgLen )
{
	if( MsgLen == 0 )
	{
		return;
	}

	ctx -> fb = (uint8_t) ( 1 << ( Msg[ MsgLen - 1 ] >> 7 ));

	if( ctx -> IsHashFilled == 0 )
	{
		ctx -> InitBytePos += MsgLen;

		if( ctx -> InitBytePos >= ctx -> HashLen * PRVHASH64S_PAR )
		{
			ctx -> IsHashFilled = 1;
		}
	}

	const uint64_t* const HashEnd =
		(uint64_t*) ( ctx -> Hash + ctx -> HashLen );

	uint64_t* hc = (uint64_t*) ( ctx -> Hash + ctx -> HashPos );

	if( ctx -> BlockFill > 0 && ctx -> BlockFill + MsgLen >= PRVHASH64S_LEN )
	{
		const size_t CopyLen = PRVHASH64S_LEN - ctx -> BlockFill;
		memcpy( ctx -> Block + ctx -> BlockFill, Msg, CopyLen );
		ctx -> BlockFill = 0;

		Msg += CopyLen;
		MsgLen -= CopyLen;

		ctx -> lcg[ 0 ] ^= prvhash_lu64ec( ctx -> Block + 0 );
		ctx -> lcg[ 1 ] ^= prvhash_lu64ec( ctx -> Block + 8 );
		ctx -> lcg[ 2 ] ^= prvhash_lu64ec( ctx -> Block + 16 );
		ctx -> lcg[ 3 ] ^= prvhash_lu64ec( ctx -> Block + 24 );

		prvhash_core64( &ctx -> Seed[ 0 ], &ctx -> lcg[ 0 ], hc );
		prvhash_core64( &ctx -> Seed[ 1 ], &ctx -> lcg[ 1 ], hc );
		prvhash_core64( &ctx -> Seed[ 2 ], &ctx -> lcg[ 2 ], hc );
		prvhash_core64( &ctx -> Seed[ 3 ], &ctx -> lcg[ 3 ], hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (uint64_t*) ctx -> Hash;
		}
	}

	if( MsgLen >= PRVHASH64S_LEN )
	{
		uint64_t Seed1 = ctx -> Seed[ 0 ];
		uint64_t Seed2 = ctx -> Seed[ 1 ];
		uint64_t Seed3 = ctx -> Seed[ 2 ];
		uint64_t Seed4 = ctx -> Seed[ 3 ];
		uint64_t lcg1 = ctx -> lcg[ 0 ];
		uint64_t lcg2 = ctx -> lcg[ 1 ];
		uint64_t lcg3 = ctx -> lcg[ 2 ];
		uint64_t lcg4 = ctx -> lcg[ 3 ];

		do
		{
			lcg1 ^= prvhash_lu64ec( Msg + 0 );
			lcg2 ^= prvhash_lu64ec( Msg + 8 );
			lcg3 ^= prvhash_lu64ec( Msg + 16 );
			lcg4 ^= prvhash_lu64ec( Msg + 24 );

			prvhash_core64( &Seed1, &lcg1, hc );
			prvhash_core64( &Seed2, &lcg2, hc );
			prvhash_core64( &Seed3, &lcg3, hc );
			prvhash_core64( &Seed4, &lcg4, hc );

			Msg += PRVHASH64S_LEN;
			MsgLen -= PRVHASH64S_LEN;

			hc++;

			if( hc == HashEnd )
			{
				hc = (uint64_t*) ctx -> Hash;
			}
		} while( MsgLen >= PRVHASH64S_LEN );

		ctx -> Seed[ 0 ] = Seed1;
		ctx -> Seed[ 1 ] = Seed2;
		ctx -> Seed[ 2 ] = Seed3;
		ctx -> Seed[ 3 ] = Seed4;
		ctx -> lcg[ 0 ] = lcg1;
		ctx -> lcg[ 1 ] = lcg2;
		ctx -> lcg[ 2 ] = lcg3;
		ctx -> lcg[ 3 ] = lcg4;
	}

	ctx -> HashPos = (uint8_t*) hc - ctx -> Hash;

	memcpy( ctx -> Block + ctx -> BlockFill, Msg, MsgLen );
	ctx -> BlockFill += MsgLen;
}

/**
 * This function finalizes the streamed hashing. This function should be
 * called only after prior prvhash64s_init() function call. This function
 * applies endianness correction automatically (on little- and big-endian
 * processors).
 *
 * @param ctx Context structure.
 */

inline void prvhash64s_final( PRVHASH64S_CTX* ctx )
{
	uint8_t fbytes[ PRVHASH64S_LEN ];
	memset( fbytes, 0, PRVHASH64S_LEN );
	fbytes[ 0 ] = ctx -> fb;

	prvhash64s_update( ctx, fbytes, PRVHASH64S_LEN - ctx -> BlockFill );

	const uint64_t* const HashEnd =
		(uint64_t*) ( ctx -> Hash + ctx -> HashLen );

	uint64_t* hc = (uint64_t*) ( ctx -> Hash + ctx -> HashPos );

	uint64_t Seed1 = ctx -> Seed[ 0 ];
	uint64_t Seed2 = ctx -> Seed[ 1 ];
	uint64_t Seed3 = ctx -> Seed[ 2 ];
	uint64_t Seed4 = ctx -> Seed[ 3 ];
	uint64_t lcg1 = ctx -> lcg[ 0 ];
	uint64_t lcg2 = ctx -> lcg[ 1 ];
	uint64_t lcg3 = ctx -> lcg[ 2 ];
	uint64_t lcg4 = ctx -> lcg[ 3 ];

	const size_t fc = sizeof( uint64_t ) +
		( ctx -> HashLen == sizeof( uint64_t ) ? 0 : ctx -> HashLen +
		( ctx -> IsHashFilled == 0 ? (uint8_t*) HashEnd - (uint8_t*) hc : 0 ));

	size_t k;

	for( k = 0; k <= fc; k += sizeof( uint64_t ))
	{
		prvhash_core64( &Seed1, &lcg1, hc );
		prvhash_core64( &Seed2, &lcg2, hc );
		prvhash_core64( &Seed3, &lcg3, hc );
		prvhash_core64( &Seed4, &lcg4, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (uint64_t*) ctx -> Hash;
		}
	}

	for( k = 0; k < ctx -> HashLen; k += sizeof( uint64_t ))
	{
		prvhash_core64( &Seed1, &lcg1, hc );
		prvhash_core64( &Seed2, &lcg2, hc );
		prvhash_core64( &Seed3, &lcg3, hc );
		*hc = prvhash_core64( &Seed4, &lcg4, hc );

		hc++;

		if( hc == HashEnd )
		{
			hc = (uint64_t*) ctx -> Hash;
		}
	}

	prvhash_ec64( ctx -> Hash, ctx -> HashLen );

	memset( ctx, 0, sizeof( PRVHASH64S_CTX ));
}

/**
 * This function calculates the "prvhash64s" hash of the specified message in
 * "oneshot" mode, with default seed settings, without using streaming
 * capabilities.
 *
 * @param Msg The message to produce hash from. The alignment of the message
 * is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[out] Hash The hash buffer, length = HashLen. On systems where this
 * is relevant, this address should be aligned to 64 bits.
 * @param HashLen The required hash length, in bytes, should be >= 8, in
 * increments of 8.
 */

inline void prvhash64s_oneshot( const uint8_t* const Msg, const size_t MsgLen,
	uint8_t* const Hash, const size_t HashLen )
{
	PRVHASH64S_CTX ctx;

	prvhash64s_init( &ctx, Hash, HashLen, 0, 0 );
	prvhash64s_update( &ctx, Msg, MsgLen );
	prvhash64s_final( &ctx );
}

#endif // PRVHASH64S_INCLUDED

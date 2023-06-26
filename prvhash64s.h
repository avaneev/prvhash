/**
 * prvhash64s.h version 4.3.3
 *
 * The inclusion file for the "prvhash64s" hash function. More secure,
 * streamed, and high-speed. Implements a fused variant of the "prvhash64"
 * hash function, with output PRNG XORing, and a self-start.
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

#ifndef PRVHASH64S_INCLUDED
#define PRVHASH64S_INCLUDED

#include "prvhash_core.h"

#define PRH64S_T uint64_t // PRVHASH state variable type.
#define PRH64S_S sizeof( PRH64S_T ) // State variable type's size.
#define PRH64S_FN prvhash_core64 // PRVHASH function name.
#define PRH64S_LUEC( v ) prvhash_lu64ec( v ) // Value load function, with EC.
#define PRH64S_EC( v ) PRVHASH_EC64( v ) // Value's endianness-correction.

#define PRH64S_MAX 512 // Maximal supported hash length, in bytes.
#define PRH64S_FUSE 4 // PRVHASH fusing.
#define PRH64S_LEN ( PRH64S_S * PRH64S_FUSE ) // Intermediate block's length.

/**
 * The context structure of the "prvhash64s_X" functions. On systems where
 * this is relevant, this structure should be aligned to PRH64S_S bytes.
 * This structure, being small, can be placed on stack.
 */

typedef struct {
	PRH64S_T Seed[ PRH64S_FUSE ]; ///< Current fused "Seed" values.
	PRH64S_T lcg[ PRH64S_FUSE ]; ///< Current fused "lcg" values.
	uint8_t Hash[ PRH64S_MAX ]; ///< Working hash buffer.
	uint8_t Block[ PRH64S_LEN ]; ///< Intermediate input data block.
	uint64_t MsgLen; ///< Message length counter, in bytes.
	size_t HashLen; ///< Hash buffer length, in bytes, >= PRH64S_S,
		///< increments of PRH64S_S.
	size_t HashPos; ///< Hash buffer position.
	size_t BlockFill; ///< The number of bytes filled in the Block.
	uint8_t fb; ///< Final stream byte value, for hashing finalization.
} PRVHASH64S_CTX;

/**
 * PRVHASH64S streaming hash function initialization (64-bit state variables)
 * This function should be called before the hashing session.
 *
 * @param[out] ctx Context structure. Should be aligned to PRH64S_S bytes.
 * @param HashLen The required hash length, in bytes; should be >= PRH64S_S,
 * in increments of PRH64S_S. Should not exceed PRH64S_MAX.
 * @param UseSeeds Optional pointer to seed entropy pool, to use instead of
 * the default seeds. To use the default seeds, set to 0. If specified, the
 * UseSeeds should point to a 32-byte array (e.g., four 64-bit values), which
 * can have any statistical quality, and can be partially set to zero. The
 * address alignment of this pointer is unimportant. The provided values will
 * be endianness-corrected automatically.
 */

static inline void prvhash64s_init( PRVHASH64S_CTX* const ctx,
	const size_t HashLen, const void* const UseSeeds )
{
	memset( ctx -> Hash, 0, HashLen );
	int i;

	if( UseSeeds == 0 )
	{
		for( i = 0; i < PRH64S_FUSE; i++ )
		{
			ctx -> Seed[ i ] = 0;
			ctx -> lcg[ i ] = 0;
		}
	}
	else
	{
		for( i = 0; i < PRH64S_FUSE; i++ )
		{
			ctx -> Seed[ i ] = PRH64S_LUEC( (const uint8_t*) UseSeeds +
				i * PRH64S_S );

			ctx -> lcg[ i ] = 0;
		}
	}

	ctx -> MsgLen = 0;
	ctx -> HashLen = HashLen;
	ctx -> HashPos = 0;
	ctx -> BlockFill = 0;
	ctx -> fb = 0;

	PRH64S_T* const hc = (PRH64S_T*) ctx -> Hash;

	PRH64S_T Seed1 = ctx -> Seed[ 0 ];
	PRH64S_T Seed2 = ctx -> Seed[ 1 ];
	PRH64S_T Seed3 = ctx -> Seed[ 2 ];
	PRH64S_T Seed4 = ctx -> Seed[ 3 ];
	PRH64S_T lcg1 = ctx -> lcg[ 0 ];
	PRH64S_T lcg2 = ctx -> lcg[ 1 ];
	PRH64S_T lcg3 = ctx -> lcg[ 2 ];
	PRH64S_T lcg4 = ctx -> lcg[ 3 ];

	for( i = 0; i < PRVHASH_INIT_COUNT; i++ )
	{
		PRH64S_FN( &Seed1, &lcg1, hc );
		PRH64S_FN( &Seed2, &lcg2, hc );
		PRH64S_FN( &Seed3, &lcg3, hc );
		PRH64S_FN( &Seed4, &lcg4, hc );
	}

	ctx -> Seed[ 0 ] = Seed1;
	ctx -> Seed[ 1 ] = Seed2;
	ctx -> Seed[ 2 ] = Seed3;
	ctx -> Seed[ 3 ] = Seed4;
	ctx -> lcg[ 0 ] = lcg1;
	ctx -> lcg[ 1 ] = lcg2;
	ctx -> lcg[ 2 ] = lcg3;
	ctx -> lcg[ 3 ] = lcg4;
}

/**
 * This function updates the hash according to the contents of the message.
 * Before this function can be called, the prvhash64s_init() should be called,
 * to initialize the context structure. When the streamed hashing is finished,
 * the prvhash64s_final() function should be called.
 *
 * @param[in,out] ctx Context structure.
 * @param Msg0 The message to produce a hash from. The address alignment of
 * this pointer is unimportant. Can be 0 if MsgLen==0.
 * @param MsgLen Message's length, in bytes; can be 0.
 */

static inline void prvhash64s_update( PRVHASH64S_CTX* const ctx,
	const void* const Msg0, size_t MsgLen )
{
	if( MsgLen == 0 )
	{
		return;
	}

	ctx -> MsgLen += (uint64_t) MsgLen;

	const uint8_t* Msg = (const uint8_t*) Msg0;
	size_t blf = ctx -> BlockFill;

	if( blf + MsgLen >= PRH64S_LEN && blf != 0 )
	{
		const size_t CopyLen = PRH64S_LEN - blf;
		memcpy( ctx -> Block + blf, Msg, CopyLen );
		blf = 0;

		Msg += CopyLen;
		MsgLen -= CopyLen;

		PRH64S_T* const hc = (PRH64S_T*) ( ctx -> Hash + ctx -> HashPos );

		ctx -> HashPos += PRH64S_S;

		if( ctx -> HashPos == ctx -> HashLen )
		{
			ctx -> HashPos = 0;
		}

		const PRH64S_T m1 = PRH64S_LUEC( ctx -> Block );
		const PRH64S_T m2 = PRH64S_LUEC( ctx -> Block + PRH64S_S );
		const PRH64S_T m3 = PRH64S_LUEC( ctx -> Block + PRH64S_S * 2 );
		const PRH64S_T m4 = PRH64S_LUEC( ctx -> Block + PRH64S_S * 3 );

		ctx -> Seed[ 0 ] ^= m1;
		ctx -> lcg[ 0 ] ^= m1;
		PRH64S_FN( &ctx -> Seed[ 0 ], &ctx -> lcg[ 0 ], hc );

		ctx -> Seed[ 1 ] ^= m2;
		ctx -> lcg[ 1 ] ^= m2;
		PRH64S_FN( &ctx -> Seed[ 1 ], &ctx -> lcg[ 1 ], hc );

		ctx -> Seed[ 2 ] ^= m3;
		ctx -> lcg[ 2 ] ^= m3;
		PRH64S_FN( &ctx -> Seed[ 2 ], &ctx -> lcg[ 2 ], hc );

		ctx -> Seed[ 3 ] ^= m4;
		ctx -> lcg[ 3 ] ^= m4;
		PRH64S_FN( &ctx -> Seed[ 3 ], &ctx -> lcg[ 3 ], hc );
	}

	if( MsgLen >= PRH64S_LEN )
	{
		const PRH64S_T* const HashEnd =
			(PRH64S_T*) ( ctx -> Hash + ctx -> HashLen );

		PRH64S_T* hc = (PRH64S_T*) ( ctx -> Hash + ctx -> HashPos );

		PRH64S_T Seed1 = ctx -> Seed[ 0 ];
		PRH64S_T Seed2 = ctx -> Seed[ 1 ];
		PRH64S_T Seed3 = ctx -> Seed[ 2 ];
		PRH64S_T Seed4 = ctx -> Seed[ 3 ];
		PRH64S_T lcg1 = ctx -> lcg[ 0 ];
		PRH64S_T lcg2 = ctx -> lcg[ 1 ];
		PRH64S_T lcg3 = ctx -> lcg[ 2 ];
		PRH64S_T lcg4 = ctx -> lcg[ 3 ];

		do
		{
			const PRH64S_T m1 = PRH64S_LUEC( Msg );
			const PRH64S_T m2 = PRH64S_LUEC( Msg + PRH64S_S );
			const PRH64S_T m3 = PRH64S_LUEC( Msg + PRH64S_S * 2 );
			const PRH64S_T m4 = PRH64S_LUEC( Msg + PRH64S_S * 3 );

			Seed1 ^= m1;
			lcg1 ^= m1;
			Seed2 ^= m2;
			lcg2 ^= m2;
			Seed3 ^= m3;
			lcg3 ^= m3;
			Seed4 ^= m4;
			lcg4 ^= m4;

			PRH64S_FN( &Seed1, &lcg1, hc );
			PRH64S_FN( &Seed2, &lcg2, hc );
			PRH64S_FN( &Seed3, &lcg3, hc );
			PRH64S_FN( &Seed4, &lcg4, hc );

			Msg += PRH64S_LEN;
			MsgLen -= PRH64S_LEN;

			if( ++hc == HashEnd )
			{
				hc = (PRH64S_T*) ctx -> Hash;
			}

		} while( MsgLen >= PRH64S_LEN );

		ctx -> Seed[ 0 ] = Seed1;
		ctx -> Seed[ 1 ] = Seed2;
		ctx -> Seed[ 2 ] = Seed3;
		ctx -> Seed[ 3 ] = Seed4;
		ctx -> lcg[ 0 ] = lcg1;
		ctx -> lcg[ 1 ] = lcg2;
		ctx -> lcg[ 2 ] = lcg3;
		ctx -> lcg[ 3 ] = lcg4;
		ctx -> HashPos = (uint8_t*) hc - ctx -> Hash;
	}

	memcpy( ctx -> Block + blf, Msg, MsgLen );
	ctx -> BlockFill = blf + MsgLen;
	ctx -> fb = Msg[ MsgLen - 1 ];
}

/**
 * This function finalizes the streamed hashing. This function should be
 * called only after a prior prvhash64s_init() function call; intermediate
 * prvhash64s_update() function call is not required. This function applies
 * endianness-correction to the resulting hash value automatically
 * (on little- and big-endian processors).
 *
 * @param[in,out] ctx Context structure. Zeroed on function's return.
 * @param[out] HashOut The hash buffer to receive the resulting hash value.
 * Buffer's size should match the HashLen specified during initialization. The
 * address alignment of this buffer is unimportant.
 */

static inline void prvhash64s_final( PRVHASH64S_CTX* const ctx,
	void* const HashOut )
{
	uint8_t fbytes[ PRH64S_LEN ];
	memset( fbytes, 0, PRH64S_LEN );

	fbytes[ PRH64S_S - 1 ] = (uint8_t) ( 1 << ( ctx -> fb >> 7 ));
	prvhash64s_update( ctx, fbytes, PRH64S_S );

	const uint64_t MsgLen = PRH64S_EC( ctx -> MsgLen );
	prvhash64s_update( ctx, &MsgLen, 8 );
	fbytes[ PRH64S_S - 1 ] = (uint8_t) ( 1 << ( ctx -> fb >> 7 ));
	prvhash64s_update( ctx, fbytes, PRH64S_S );

	if( ctx -> BlockFill > 0 )
	{
		fbytes[ PRH64S_S - 1 ] = 0;
		prvhash64s_update( ctx, fbytes, PRH64S_LEN - ctx -> BlockFill );
	}

	const PRH64S_T* const HashEnd =
		(PRH64S_T*) ( ctx -> Hash + ctx -> HashLen );

	PRH64S_T* hc = (PRH64S_T*) ( ctx -> Hash + ctx -> HashPos );

	PRH64S_T Seed1 = ctx -> Seed[ 0 ];
	PRH64S_T Seed2 = ctx -> Seed[ 1 ];
	PRH64S_T Seed3 = ctx -> Seed[ 2 ];
	PRH64S_T Seed4 = ctx -> Seed[ 3 ];
	PRH64S_T lcg1 = ctx -> lcg[ 0 ];
	PRH64S_T lcg2 = ctx -> lcg[ 1 ];
	PRH64S_T lcg3 = ctx -> lcg[ 2 ];
	PRH64S_T lcg4 = ctx -> lcg[ 3 ];

	const size_t fc = PRH64S_S + ( ctx -> HashLen == PRH64S_S ? 0 :
		ctx -> HashLen + ( ctx -> MsgLen < ctx -> HashLen * PRH64S_FUSE ?
		(uint8_t*) HashEnd - (uint8_t*) hc : 0 ));

	size_t k;

	for( k = 0; k <= fc; k += PRH64S_S )
	{
		PRH64S_FN( &Seed1, &lcg1, hc );
		PRH64S_FN( &Seed2, &lcg2, hc );
		PRH64S_FN( &Seed3, &lcg3, hc );
		PRH64S_FN( &Seed4, &lcg4, hc );

		if( ++hc == HashEnd )
		{
			hc = (PRH64S_T*) ctx -> Hash;
		}
	}

	uint8_t* const ho = (uint8_t*) HashOut;

	for( k = 0; k < ctx -> HashLen; k += PRH64S_S )
	{
		PRH64S_T res = 0;
		int i;

		for( i = 0; i < 4; i++ )
		{
			PRH64S_FN( &Seed1, &lcg1, hc );
			PRH64S_FN( &Seed2, &lcg2, hc );
			PRH64S_FN( &Seed3, &lcg3, hc );
			res ^= PRH64S_FN( &Seed4, &lcg4, hc );

			if( ++hc == HashEnd )
			{
				hc = (PRH64S_T*) ctx -> Hash;
			}
		}

		res = PRH64S_EC( res );
		memcpy( ho + k, &res, PRH64S_S );
	}

	memset( ctx, 0, sizeof( PRVHASH64S_CTX ));
}

/**
 * This function calculates the "prvhash64s" hash of the specified message in
 * the "oneshot" mode, with default seed settings, without using streaming
 * capabilities.
 *
 * @param Msg The message to produce a hash from. The alignment of this
 * pointer is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param[out] Hash The hash buffer, length = HashLen. The address alignment
 * of this buffer is unimportant.
 * @param HashLen The required hash length, in bytes; should be >= PRH64S_S,
 * in increments of PRH64S_S. Should not exceed PRH64S_MAX.
 */

static inline void prvhash64s_oneshot( const void* const Msg,
	const size_t MsgLen, void* const Hash, const size_t HashLen )
{
	PRVHASH64S_CTX ctx;

	prvhash64s_init( &ctx, HashLen, 0 );
	prvhash64s_update( &ctx, Msg, MsgLen );
	prvhash64s_final( &ctx, Hash );
}

#endif // PRVHASH64S_INCLUDED

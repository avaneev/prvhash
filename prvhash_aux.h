/**
 * prvhash_aux.h version 3.3.1
 *
 * The inclusion file for the auxiliary functions used by PRVHASH hashing
 * functions.
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

#ifndef PRVHASH_AUX_INCLUDED
#define PRVHASH_AUX_INCLUDED

#include <stdint.h>
#include <string.h>

#if defined( _WIN32 ) || defined( __LITTLE_ENDIAN__ ) || ( defined( __BYTE_ORDER__ ) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )
	#define PRVHASH_LITTLE_ENDIAN 1
#elif defined( __BIG_ENDIAN__ ) || ( defined( __BYTE_ORDER__ ) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )
	#define PRVHASH_LITTLE_ENDIAN 0
#else // endianness check
	#error PRVHASH: cannot obtain endianness
#endif // endianness check

#if PRVHASH_LITTLE_ENDIAN

/**
 * An macro that applies byte-swapping used for endianness-correction.
 */

#define PRVHASH_EC64( v ) ( v )

#else // PRVHASH_LITTLE_ENDIAN

#if defined( __GNUC__ ) || defined( __clang__ )

#define PRVHASH_EC64( v ) __builtin_bswap64( v )

#elif defined( _MSC_VER ) || defined( __INTEL_COMPILER )

#define PRVHASH_EC64( v ) _byteswap_uint64( v )

#endif // defined( _MSC_VER ) || defined( __INTEL_COMPILER )

#endif // PRVHASH_LITTLE_ENDIAN

/**
 * An auxiliary function that returns an unsigned 64-bit value created out of
 * individual bytes in a buffer. This function is used to convert endianness
 * of supplied 64-bit unsigned values, and to avoid unaligned memory accesses.
 *
 * @param p 8-byte buffer. Alignment is unimportant.
 */

inline uint64_t prvhash_lu64ec( const uint8_t* const p )
{
	uint64_t v;
	memcpy( &v, p, 8 );

	return( PRVHASH_EC64( v ));
}

#if PRVHASH_LITTLE_ENDIAN

/**
 * This function corrects (inverses) endianness of the specified hash value,
 * based on 64-bit words.
 *
 * @param[in,out] Hash The hash to correct endianness of. On systems where
 * this is relevant, this address should be aligned to 64 bits.
 * @param HashLen The required hash length, in bytes, should be >= 8, in
 * increments of 8. 
 */

inline void prvhash_ec64( uint8_t* const Hash, const size_t HashLen )
{
}

#else // PRVHASH_LITTLE_ENDIAN

inline void prvhash_ec64( uint8_t* const Hash, const size_t HashLen )
{
	size_t k;

	for( k = 0; k < HashLen; k += sizeof( uint64_t ))
	{
		*(uint64_t*) ( Hash + k ) = PRVHASH_EC64( *(uint64_t*) ( Hash + k ));
	}
}

#endif // PRVHASH_LITTLE_ENDIAN

/**
 * Function loads 64-bit message word and pads it with the "final byte". This
 * function should only be called if there is less than 8 bytes left to read.
 *
 * @param Msg Message pointer, alignment is unimportant. Should be below or
 * equal to MsgEnd.
 * @param MsgEnd Message's end pointer.
 * @param fb Final byte used for padding.
 */

inline uint64_t prvhash_lpu64_f( const uint8_t* Msg,
	const uint8_t* const MsgEnd, const uint64_t fb )
{
	uint64_t r = fb << (( MsgEnd - Msg ) << 3 );

	if( Msg < MsgEnd )
	{
		r |= *Msg;
		Msg++;

		if( Msg < MsgEnd )
		{
			r |= (uint64_t) *Msg << 8;
			Msg++;

			if( Msg < MsgEnd )
			{
				r |= (uint64_t) *Msg << 16;
				Msg++;

				if( Msg < MsgEnd )
				{
					r |= (uint64_t) *Msg << 24;
					Msg++;

					if( Msg < MsgEnd )
					{
						r |= (uint64_t) *Msg << 32;
						Msg++;

						if( Msg < MsgEnd )
						{
							r |= (uint64_t) *Msg << 40;
							Msg++;

							if( Msg < MsgEnd )
							{
								r |= (uint64_t) *Msg << 48;
							}
						}
					}
				}
			}
		}
	}

	return( r );
}

#endif // PRVHASH_AUX_INCLUDED

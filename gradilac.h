/**
 * gradilac.h version 4.3.3
 *
 * The inclusion file for the "Gradilac", a flexible templated C++ PRNG, based
 * on the PRVHASH core function. Standalone class, does not require PRVHASH
 * header files.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * License
 *
 * Copyright (c) 2022 Aleksey Vaneev
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

#ifndef GRADILAC_INCLUDED
#define GRADILAC_INCLUDED

#include <stdint.h>
#include <string.h>
#include <math.h>

/**
 * Templated PRVHASH core function. For more information, please refer to the
 * "prvhash_core64" function in the "prvhash_core.h" file.
 *
 * @param[in,out] Seed0 The current "Seed" value.
 * @param[in,out] lcg0 The current "lcg" value.
 * @param[in,out] Hash0 Current hashword in a hashword array.
 * @return Current random value.
 * @tparam stype State variable type, must be unsigned type, up to 64 bits.
 */

template< typename stype >
static inline stype prvhash_core( stype* const Seed0,
	stype* const lcg0, stype* const Hash0 )
{
	const int sh = sizeof( stype ) * 4;

	stype Seed = *Seed0; stype lcg = *lcg0; stype Hash = *Hash0;

	Seed *= (stype) ( lcg * 2 + 1 );
	const stype rs = (stype) ( Seed >> sh | Seed << sh );
	Hash += (stype) ( rs + (stype) 0xAAAAAAAAAAAAAAAA );
	lcg += (stype) ( Seed + (stype) 0x5555555555555555 );
	Seed ^= Hash;
	const stype out = lcg ^ rs;

	*Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;

	return( out );
}

/**
 * Generalized templated PRVHASH-based PRNG class.
 *
 * Objects of this class do not use memory allocations and can be placed on
 * stack (if "hcount" is not large).
 *
 * Note that random values returned by functions of this class return values
 * in the "exclusive" range only, [0; 1) or [0; N). Also note that precision
 * of floating-point random numbers depends on the "stype" in use.
 *
 * @tparam hcount The number of hashwords in array, must be >0. E.g. use 316
 * and 64-bit "stype" to match Mersenne Twister's PRNG period.
 * @tparam stype State variable type, must be unsigned integer type, up to 64
 * bits wide. Using "stype" smaller than 24 bits is not advised.
 * @tparam par PRVHASH parallelism, must be >= 0. Should be above 0 if PRNG
 * output may be used as entropy input (output feedback), usually in open
 * systems.
 * @tparam cs Must be >= 0. If above 0, enable CSPRNG mode. "cs" defines the
 * number of additional PRNG rounds and XOR operations.
 */

template< size_t hcount = 1, typename stype = uint64_t, int par = 1,
	int cs = 0 >
class Gradilac
{
public:
	/**
	 * Constructor. Note that copy-constructor and copy operator remain
	 * default as class has no complex structures.
	 *
	 * @param iseed Initial "small" seed, can be zero.
	 */

	Gradilac( const stype iseed = 0 )
	{
		seed( iseed );
	}

	/**
	 * Function initializes/reinitializes the PRNG. This is not the on-the-run
	 * re-seeding. In CSPRNG mode, the "reseed" function should be then used.
	 *
	 * @param iseed Initial "small" seed, can be zero.
	 */

	void seed( const stype iseed = 0 )
	{
		memset( Seed, 0, par * sizeof( Seed[ 0 ]));
		memset( lcg, 0, par * sizeof( lcg[ 0 ]));
		memset( Hash, 0, hcount * sizeof( Hash[ 0 ]));

		Seed[ 0 ] = iseed;
		hpos = 0;
		BitPool = 0;
		BitsLeft = 0;

		// Initialization involving only the first hashword, other zero
		// hashwords will be initalized on the run.

		int j;

		for( j = 0; j < 5; j++ )
		{
			int i;

			for( i = 0; i < par; i++ )
			{
				prvhash_core( Seed + i, lcg + i, Hash + 0 );
			}
		}
	}

	/**
	 * Function re-seeds PRNG on-the-run using a single entropy value. This
	 * function is not advised for use in CSPRNG mode. This function can be
	 * used to efficiently adjust initial seed after the default constructor
	 * call (iseed=0).
	 *
	 * @param ent Entropy value (can be any value).
	 */

	void reseed( const stype ent )
	{
		Seed[ 0 ] ^= ent;
		lcg[ 0 ] ^= ent;

		getInt();

		if( par > 1 )
		{
			getInt();
		}
	}

	/**
	 * Function re-seeds PRNG, starting from the current state, and using the
	 * specified data as entropy. This function should be used in CSPRNG mode.
	 *
	 * @param data Entropy data block, can be of any length and of any
	 * statistical quality. Usually it is any sequence of physics-dependent
	 * data from physical sources like timer, keyboard, mouse, network. Or
	 * from system's CSPRNG.
	 * @param dlen Data length, in bytes.
	 * @param psize Packet size, in bytes, >= 1. Should not exceed the size of
	 * "stype". The data will be divided into packets of this size per PRNG
	 * advancement. This value affects initialization overhead. Value of 1 is
	 * advised for sparsely-random data. High-quality entropy can use
	 * sizeof( stype ).
	 */

	void reseed( const void* const data, size_t dlen, const size_t psize = 1 )
	{
		const uint8_t* d = (const uint8_t*) data;

		while( dlen > 0 )
		{
			size_t l = ( psize > dlen ? dlen : psize );
			dlen -= l;
			stype p = 0; // Packet.

			while( l > 0 )
			{
				p <<= 8;
				p |= *d;

				d++;
				l--;
			}

			Seed[ 0 ] ^= p;
			lcg[ 0 ] ^= p;

			getInt();
		}

		// Make hashword array pass to eliminate traces of input entropy.

		int i;

		for( i = 0; i < hcount + ( hcount > 1 ) + ( par > 1 ); i++ )
		{
			getInt();
		}
	}

	/**
	 * @return The next floating-point random number in [0; 1) range.
	 */

	double get()
	{
		if( sizeof( stype ) * 8 > 53 )
		{
			return(( getInt() >> ( sizeof( stype ) * 8 - 53 )) * 0x1p-53 );
		}
		else
		{
			return( getInt() * im() );
		}
	}

	/**
	 * @return The next floating-point random number in [0; N1) range.
	 */

	double get( const double N1 )
	{
		if( sizeof( stype ) * 8 > 53 )
		{
			return(( getInt() >> ( sizeof( stype ) * 8 - 53 )) *
				0x1p-53 * N1 );
		}
		else
		{
			return( getInt() * im() * N1 );
		}
	}

	/**
	 * Operator "object as function", for easier integration, same as the
	 * get() function.
	 */

	double operator()()
	{
		return( get() );
	}

	/**
	 * @return The next random integer number in the "raw", stype-value range.
	 * This is the actual PRNG advancement function.
	 */

	stype getInt()
	{
		stype* h = Hash + hpos;

		if( ++hpos == hcount )
		{
			hpos = 0;
		}

		int i;

		for( i = 0; i < par - 1; i++ )
		{
			prvhash_core( Seed + i, lcg + i, h );
		}

		stype res = prvhash_core( Seed + i, lcg + i, h );

		int j;

		for( j = 0; j < cs; j++ )
		{
			h = Hash + hpos;

			if( ++hpos == hcount )
			{
				hpos = 0;
			}

			for( i = 0; i < par - 1; i++ )
			{
				prvhash_core( Seed + i, lcg + i, h );
			}

			res ^= prvhash_core( Seed + i, lcg + i, h );
		}

		return( res );
	}

	/**
	 * @return The next random integer number in [0; N1) range (note the N's
	 * exclusivity). N1 specifies positive number of discrete bins, and not
	 * the extreme value.
	 */

	stype getInt( const stype N1 )
	{
		return( (stype) get( N1 ));
	}

	/**
	 * @return The next squared floating-point random number in [0; 1) range.
	 * This is Beta distribution, with alpha=0.5, beta=1.
	 */

	double getSqr()
	{
		const double v = get();

		return( v * v );
	}

	/**
	 * @return TPDF random number in the range (-1; 1). Note that this
	 * function uses an optimized variant, with 32-bit precision, when
	 * stype=uint64_t.
	 */

	double getTPDF()
	{
		if( sizeof( stype ) == 8 )
		{
			const stype rv = getInt();

			return(( (int64_t) ( rv >> 32 ) - (int64_t) (uint32_t) rv ) *
				0x1p-32 );
		}
		else
		if( sizeof( stype ) * 8 > 53 )
		{
			const double v1 = get();
			const double v2 = get();

			return( v1 - v2 );
		}
		else
		{
			const double v1 = (double) getInt();
			const double v2 = (double) getInt();

			return(( v1 - v2 ) * im() );
		}
	}

	/**
	 * Function generates a Gaussian (normal)-distributed pseudo-random number
	 * with the specified mean and std.dev.
	 *
	 * Algorithm is adopted from "Leva, J. L. 1992. "A Fast Normal Random
	 * Number Generator", ACM Transactions on Mathematical Software, vol. 18,
	 * no. 4, pp. 449-453".
	 */

	double getNorm( const double mean = 0.0, const double stddev = 1.0 )
	{
		double q, u, v;

		do
		{
			u = get();
			v = get();

			if( u <= 0.0 || v <= 0.0 )
			{
				u = 1.0;
				v = 1.0;
			}

			v = 1.7156 * ( v - 0.5 );
			const double x = u - 0.449871;
			const double y = fabs( v ) + 0.386595;
			q = x * x + y * ( 0.19600 * y - 0.25472 * x );

			if( q < 0.27597 )
			{
				break;
			}
		} while(( q > 0.27846 ) || ( v * v > -4.0 * log( u ) * u * u ));

		return( mean + stddev * v / u );
	}

	/**
	 * @return The next random bit from the bit pool. Usually used for
	 * efficient 50% probability evaluations.
	 */

	int getBit()
	{
		if( BitsLeft == 0 )
		{
			BitPool = getInt();

			const int b = BitPool & 1;

			BitsLeft = sizeof( stype ) * 8 - 1;
			BitPool >>= 1;

			return( b );
		}

		const int b = BitPool & 1;

		BitsLeft--;
		BitPool >>= 1;

		return( b );
	}

	/**
	 * @return PRNG period's exponent (2^N) estimation.
	 */

	static size_t getPeriodExp()
	{
		return(( par * 8 + par * 4 + hcount * 8 ) * sizeof( stype ) -
			hcount );
	}

protected:
	stype Seed[ par ]; ///< PRNG seeds (>1 - parallel).
		///<
	stype lcg[ par ]; ///< PRNG lcg (>1 - parallel).
		///<
	stype Hash[ hcount ]; ///< PRNG hash array.
		///<
	size_t hpos; ///< Hash array position (increments linearly, resets to 0).
		///<
	stype BitPool; ///< Bit pool, optional feature.
		///<
	int BitsLeft; ///< The number of bits left in the bit pool.
		///<

	/**
	 * @return Inverse multiplier to scale stype's value range to [0; 1)
	 * range.
	 */

	static double im()
	{
		static const double v = 0.5 / ( 1ULL << ( sizeof( stype ) * 8 - 1 ));

		return( v );
	}
};

#endif // GRADILAC_INCLUDED

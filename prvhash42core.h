/**
 * prvhash42core.h version 2.27
 *
 * The inclusion file for the "prvhash42_core64", "prvhash42_core32",
 * "prvhash42_core16", "prvhash42_core8", "prvhash42_core4",
 * "prvhash42_core2" PRVHASH core functions for various state-variable sizes
 * and hash-word sizes.
 *
 * Description is available at https://github.com/avaneev/prvhash
 *
 * Copyright (c) 2020 Aleksey Vaneev; All rights reserved.
 */

#ifndef PRVHASH42CORE_INCLUDED
#define PRVHASH42CORE_INCLUDED

#include <stdint.h>

/**
 * This function runs a single PRVHASH random number generation round. This
 * function can be used both as a hash generator and as a general-purpose
 * random number generator. In the latter case, it is advisable to initially
 * run this function at least 4 times before using its random output, to
 * neutralize any possible oddities of "Seed"'s and "lcg"'s initial values.
 *
 * To generate hashes, the "lcg" variable should be XORed with entropy input
 * prior to calling this function.
 *
 * @param[in,out] Seed The current "Seed" value. Can be initialized to any
 * value.
 * @param[in,out] lcg The current "lcg" value. Can be initialized to any
 * value.
 * @param[in,out] Hash Current hash word in a hash word array.
 * @return Current random value.
 */

inline uint32_t prvhash42_core64( uint64_t& Seed, uint64_t& lcg,
	uint32_t& Hash )
{
	const uint64_t xr = ~lcg;
	Seed += lcg;
	Seed *= lcg - xr;
	lcg += ~Seed;
	const uint64_t hs = Seed >> 32;
	const uint64_t out = Seed ^ hs;
	const uint64_t ph = Hash ^ hs;
	Seed ^= ph;
	Hash = (uint32_t) ph;

	return( (uint32_t) out );
}

inline uint16_t prvhash42_core32( uint32_t& Seed, uint32_t& lcg,
	uint16_t& Hash )
{
	const uint32_t xr = ~lcg;
	Seed += lcg;
	Seed *= lcg - xr;
	lcg += ~Seed;
	const uint32_t hs = Seed >> 16;
	const uint32_t out = Seed ^ hs;
	const uint32_t ph = Hash ^ hs;
	Seed ^= ph;
	Hash = (uint16_t) ph;

	return( (uint16_t) out );
}

inline uint8_t prvhash42_core16( uint16_t& Seed, uint16_t& lcg,
	uint8_t& Hash )
{
	const uint16_t xr = ~lcg;
	Seed += lcg;
	Seed *= lcg - xr;
	lcg += ~Seed;
	const uint16_t hs = Seed >> 8;
	const uint16_t out = Seed ^ hs;
	const uint16_t ph = Hash ^ hs;
	Seed ^= ph;
	Hash = (uint8_t) ph;

	return( (uint8_t) out );
}

inline uint8_t prvhash42_core8( uint8_t& Seed, uint8_t& lcg,
	uint8_t& Hash )
{
	const uint8_t xr = ~lcg;
	Seed += lcg;
	Seed *= lcg - xr;
	lcg += ~Seed;
	const uint8_t hs = Seed >> 4;
	const uint8_t out = Seed ^ hs;
	const uint8_t ph = ( Hash ^ hs ) & 15;
	Seed ^= ph;
	Hash = ph;

	return( out & 15 );
}

inline uint8_t prvhash42_core4( uint8_t& Seed, uint8_t& lcg,
	uint8_t& Hash )
{
	const uint8_t xr = ~lcg & 15;
	Seed += lcg;
	Seed &= 15;
	Seed *= ( lcg - xr ) & 15;
	Seed &= 15;
	lcg += ~Seed;
	lcg &= 15;
	const uint8_t hs = Seed >> 2;
	const uint8_t out = Seed ^ hs;
	const uint8_t ph = ( Hash ^ hs ) & 3;
	Seed ^= ph;
	Hash = ph;

	return( out & 3 );
}

inline uint8_t prvhash42_core2( uint8_t& Seed, uint8_t& lcg,
	uint8_t& Hash )
{
	const uint8_t xr = ~lcg & 3;
	Seed += lcg;
	Seed &= 3;
	Seed *= ( lcg - xr ) & 3;
	Seed &= 3;
	lcg += ~Seed;
	lcg &= 3;
	const uint8_t hs = Seed >> 1;
	const uint8_t out = Seed ^ hs;
	const uint8_t ph = ( Hash ^ hs ) & 1;
	Seed ^= ph;
	Hash = ph;

	return( out & 1 );
}

#endif // PRVHASH42CORE_INCLUDED1

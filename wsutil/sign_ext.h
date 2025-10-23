/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_SIGN_EXT_H__
#define __WSUTIL_SIGN_EXT_H__

#include <inttypes.h>

#include <glib.h>

#include <wsutil/ws_assert.h>

/* sign extension routines */

/**
 * @brief Sign-extends a 32-bit unsigned value from a given bit width.
 *
 * Interprets the input value as a signed integer of `no_of_bits` width and
 * extends the sign bit to the full 32-bit range. This is useful when decoding
 * signed fields packed into smaller bit widths.
 *
 * @param val The unsigned 32-bit value to sign-extend.
 * @param no_of_bits The number of significant bits (0–32).
 * @return The sign-extended 32-bit value.
 */
static inline uint32_t
ws_sign_ext32(uint32_t val, int no_of_bits)
{
	ws_assert (no_of_bits >= 0 && no_of_bits <= 32);

	if ((no_of_bits == 0) || (no_of_bits == 32))
		return val;

	/*
	 * Don't shift signed values left; that's not valid in C99, at
	 * least, if the value is negative or if the shift count is
	 * the number of bits in the value - 1, and we might get
	 * compile-time or run-time complaints about that.
	 */
	if (val & (1U << (no_of_bits-1)))
		val |= (0xFFFFFFFFU << no_of_bits);

	return val;
}

/**
 * @brief Sign-extends a 64-bit unsigned value from a given bit width.
 *
 * Interprets the input value as a signed integer of `no_of_bits` width and
 * extends the sign bit to the full 64-bit range. This is useful when decoding
 * signed fields packed into smaller bit widths.
 *
 * @param val The unsigned 64-bit value to sign-extend.
 * @param no_of_bits The number of significant bits (0–64).
 * @return The sign-extended 64-bit value.
 */
static inline uint64_t
ws_sign_ext64(uint64_t val, int no_of_bits)
{
	ws_assert (no_of_bits >= 0 && no_of_bits <= 64);

	if ((no_of_bits == 0) || (no_of_bits == 64))
		return val;

	/*
	 * Don't shift signed values left; that's not valid in C99, at
	 * least, if the value is negative or if the shift count is
	 * the number of bits in the value - 1, and we might get
	 * compile-time or run-time complaints about that.
	 */
	if (val & (UINT64_C(1) << (no_of_bits-1)))
		val |= (UINT64_C(0xFFFFFFFFFFFFFFFF) << no_of_bits);

	return val;
}

/*
static inline uint64_t
ws_sign_ext64(uint64_t val, int no_of_bits)
{
	int64_t sval = (val << (64 - no_of_bits));

	return (uint64_t) (sval >> (64 - no_of_bits));
}
*/

#endif /* __WSUTIL_SIGN_EXT_H__ */

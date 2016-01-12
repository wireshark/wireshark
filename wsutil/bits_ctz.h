/*
 * bitz_ctz.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __WSUTIL_BITS_CTZ_H__
#define __WSUTIL_BITS_CTZ_H__

#include <glib.h>

/* ws_ctz == trailing zeros == position of lowest set bit [0..63] */
/* ws_ilog2 == position of highest set bit == 63 - leading zeros [0..63] */

/* The return value of both ws_ctz and ws_ilog2 is undefined for x == 0 */

#if defined(__GNUC__) && ((__GNUC__ > 3) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))

static inline int
ws_ctz(guint64 x)
{
	return __builtin_ctzll(x);
}

static inline int
ws_ilog2(guint64 x)
{
	return 63 - __builtin_clzll(x);
}

#else

static inline int
__ws_ctz32(guint32 x)
{
	/* From http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightMultLookup */
	static const guint8 table[32] = {
		0,   1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
		31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9
	};

	return table[((guint32)((x & -(gint32)x) * 0x077CB531U)) >> 27];
}

static inline int
ws_ctz(guint64 x)
{
	guint32 hi = x >> 32;
	guint32 lo = (guint32) x;

	if (lo == 0)
		return 32 + __ws_ctz32(hi);
	else
		return __ws_ctz32(lo);
}

static inline int
__ws_ilog2_32(guint32 x)
{
	/* From http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn */
	static const guint8 table[32] =	{
		0,  9,  1, 10, 13, 21,  2, 29, 11, 14, 16, 18, 22, 25,  3, 30,
		8, 12, 20, 28, 15, 17, 24,  7, 19, 27, 23,  6, 26,  5,  4, 31
	};

	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return table[((guint32)(x * 0x07C4ACDDU)) >> 27];
}

static inline int
ws_ilog2(guint64 x)
{
	guint32 hi = x >> 32;
	guint32 lo = (guint32) x;

	if (hi == 0)
		return __ws_ilog2_32(lo);
	else
		return 32 + __ws_ilog2_32(hi);
}

#endif

#endif /* __WSUTIL_BITS_CTZ_H__ */

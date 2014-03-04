/*
 * bits_count_ones.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef __WSUTIL_BITS_COUNT_ONES_H__
#define __WSUTIL_BITS_COUNT_ONES_H__

#include "config.h"

#include <glib.h>

/*
 * The variable-precision SWAR algorithm is an interesting way to count
 * the number of bits set in an integer. While its performance is very
 * good (two times faster than gcc's __builtin_popcount [1] and
 * 16 instructions when compiled with gcc -O3)
 * http://playingwithpointers.com/swar.html
 */

static inline int
ws_count_ones(const guint32 x)
{
	int bits = x;

	bits = bits - ((bits >> 1) & 0x55555555);
	bits = (bits & 0x33333333) + ((bits >> 2) & 0x33333333);
	bits = (bits + (bits >> 4)) & 0x0F0F0F0F;

	return (bits * 0x01010101) >> 24;
}

#endif /* __WSUTIL_BITS_COUNT_ONES_H__ */

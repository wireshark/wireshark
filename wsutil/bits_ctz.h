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

static inline int
ws_ctz(guint32 x)
{
#if defined(__GNUC__) && ((__GNUC__ > 3) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
	g_assert(x != 0);

	return __builtin_ctz(x);
#else
	/* From http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightMultLookup */
	static const int table[32] = {
		0,   1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
		31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9
	};

	return table[((guint32)((x & -(gint32)x) * 0x077CB531U)) >> 27];
#endif
}

#endif /* __WSUTIL_BITS_CTZ_H__ */

/*
 * sign_ext.h
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

#ifndef __WSUTIL_SIGN_EXT_H__
#define __WSUTIL_SIGN_EXT_H__

#include <glib.h>

/* sign extension routines */

static inline guint32
ws_sign_ext32(guint32 val, int no_of_bits)
{
	g_assert (no_of_bits >= 0 && no_of_bits <= 32);

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

static inline guint64
ws_sign_ext64(guint64 val, int no_of_bits)
{
	g_assert (no_of_bits >= 0 && no_of_bits <= 64);

	if ((no_of_bits == 0) || (no_of_bits == 64))
		return val;

	/*
	 * Don't shift signed values left; that's not valid in C99, at
	 * least, if the value is negative or if the shift count is
	 * the number of bits in the value - 1, and we might get
	 * compile-time or run-time complaints about that.
	 */
	if (val & (G_GUINT64_CONSTANT(1) << (no_of_bits-1)))
		val |= (G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF) << no_of_bits);

	return val;
}

/*
static inline guint64
ws_sign_ext64(guint64 val, int no_of_bits)
{
	gint64 sval = (val << (64 - no_of_bits));

	return (guint64) (sval >> (64 - no_of_bits));
}
*/

#endif /* __WSUTIL_SIGN_EXT_H__ */

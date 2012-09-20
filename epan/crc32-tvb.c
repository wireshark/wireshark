/* crc32-tvb.c
 * CRC-32 tvbuff routines
 *
 * $Id$
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
 * Credits:
 *
 * Table from Solomon Peachy
 * Routine from Chris Waters
 */

#include "config.h"

#include <glib.h>
#include <epan/tvbuff.h>
#include <wsutil/crc32.h>


guint32
crc32_ccitt_tvb(tvbuff_t *tvb, guint len)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, 0, len);

	return ( crc32_ccitt_seed(buf, len, CRC32_CCITT_SEED) );
}

guint32
crc32_ccitt_tvb_offset(tvbuff_t *tvb, guint offset, guint len)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, offset, len);

	return ( crc32_ccitt(buf, len) );
}

guint32
crc32_ccitt_tvb_seed(tvbuff_t *tvb, guint len, guint32 seed)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, 0, len);

	return ( crc32_ccitt_seed(buf, len, seed) );
}

guint32
crc32_ccitt_tvb_offset_seed(tvbuff_t *tvb, guint offset, guint len,
			    guint32 seed)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, offset, len);

	return ( crc32_ccitt_seed(buf, len, seed) );
}

/*
 * IEEE 802.x version (Ethernet and 802.11, at least) - byte-swap
 * the result of "crc32()".
 *
 * XXX - does this mean we should fetch the Ethernet and 802.11
 * FCS with "tvb_get_letohl()" rather than "tvb_get_ntohl()",
 * or is fetching it big-endian and byte-swapping the CRC done
 * to cope with 802.x sending stuff out in reverse bit order?
 */
guint32
crc32_802_tvb(tvbuff_t *tvb, guint len)
{
	guint32 c_crc;

	c_crc = crc32_ccitt_tvb(tvb, len);

	/* Byte reverse. */
	c_crc = GUINT32_SWAP_LE_BE(c_crc);

	return ( c_crc );
}

guint32
crc32_mpeg2_tvb_offset_seed(tvbuff_t *tvb, guint offset,
                                       guint len, guint32 seed)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, offset, len);

	return ( crc32_mpeg2_seed(buf, len, seed) );
}

guint32
crc32_mpeg2_tvb(tvbuff_t *tvb, guint len)
{
    return ( crc32_mpeg2_tvb_offset_seed(tvb, 0, len, CRC32_MPEG2_SEED) );
}

guint32
crc32_mpeg2_tvb_offset(tvbuff_t *tvb, guint offset, guint len)
{
    return ( crc32_mpeg2_tvb_offset_seed(tvb, offset, len, CRC32_MPEG2_SEED) );
}

guint32
crc32_mpeg2_tvb_seed(tvbuff_t *tvb, guint len, guint32 seed)
{
    return ( crc32_mpeg2_tvb_offset_seed(tvb, 0, len, seed) );
}

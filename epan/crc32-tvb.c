/* crc32-tvb.c
 * CRC-32 tvbuff routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <epan/crc32-tvb.h>


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

guint32
crc32c_tvb_offset_calculate(tvbuff_t *tvb, guint offset, guint len, guint32 seed)
{
	const guint8* buf;

	tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, offset, len);

	return ( crc32c_calculate(buf, len, seed) );
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

guint32 crc32_0x0AA725CF_tvb_offset_seed(tvbuff_t *tvb,
					 guint offset, guint len, guint32 seed)
{
	const guint8 *buf;

	tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
	buf = tvb_get_ptr(tvb, offset, len);

	return crc32_0x0AA725CF_seed(buf, len, seed);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

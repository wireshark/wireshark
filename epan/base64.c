/* base64.c
 * Base-64 conversion
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "base64.h"

/* Decode a base64 string in-place - simple and slow algorithm.
   Return length of result. Taken from rproxy/librsync/base64.c by
   Andrew Tridgell. */

size_t epan_base64_decode(char *s)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\r\n";
	int bit_offset, byte_offset, idx, i;
	unsigned char *d = (unsigned char *)s;
	char *p;
	int  cr_idx;

	/* we will allow CR and LF - but ignore them */
	cr_idx = strchr(b64, '\r') - b64;

	i=0;

	while (*s && (p=strchr(b64, *s))) {
		idx = (int)(p - b64);
		if(idx < cr_idx) {
			byte_offset = (i*6)/8;
			bit_offset = (i*6)%8;
			d[byte_offset] &= ~((1<<(8-bit_offset))-1);
			if (bit_offset < 3) {
				d[byte_offset] |= (idx << (2-bit_offset));
			} else {
				d[byte_offset] |= (idx >> (bit_offset-2));
				d[byte_offset+1] = 0;
				d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			}
			i++;
		}
		s++; 
	}

	return i*3/4;
}

/* Return a tvb that contains the binary representation of a base64
   string */

tvbuff_t *
base64_to_tvb(const char *base64)
{
  tvbuff_t *tvb;
  char *data = g_strdup(base64);
  size_t len;

  len = epan_base64_decode(data);
  tvb = tvb_new_real_data((const guint8 *)data, len, len);

  tvb_set_free_cb(tvb, g_free);

  return tvb;
}
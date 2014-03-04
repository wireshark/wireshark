/* base64.c
 * Base-64 conversion
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
 */

#include "config.h"

#include <string.h>
#include "base64.h"

/* Decode a base64 string in-place - simple and slow algorithm.
   Return length of result. Taken from rproxy/librsync/base64.c by
   Andrew Tridgell. */

size_t ws_base64_decode_inplace(char *s)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\r\n";
	int bit_offset, byte_offset, idx, i;
	unsigned char *d = (unsigned char *)s;
	char *p;
	int  cr_idx;

	/* we will allow CR and LF - but ignore them */
	cr_idx = (int) (strchr(b64, '\r') - b64);

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

	d[i*3/4] = 0;
	return i*3/4;
}

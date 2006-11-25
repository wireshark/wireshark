/* drmcrc.c
 * another CRC 16
 * Copyright 2006, British Broadcasting Corporation 
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include "crcdrm.h"

unsigned long crc_drm(const char *data, size_t bytesize,
	unsigned short num_crc_bits, unsigned long crc_gen, int invert)
{
	unsigned long crc_holder, ones, i, msb, databit;
	signed short j;

	ones = (1 << num_crc_bits) - 1;
	crc_holder = ones;
	for (i=0; i<bytesize; i++)
		for (j=7; j>=0; j--)
		{
			crc_holder <<= 1;
			msb = crc_holder >> num_crc_bits;
			databit = (data[i] >> j) & 1;
			if ((msb ^ databit) != 0)
				crc_holder = crc_holder ^ crc_gen;
			crc_holder = crc_holder & ones;
		}
	if (invert)
		crc_holder = crc_holder ^ ones; /* invert checksum */
	return crc_holder;
}

/*
 *  crc6.c
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
 */

#include "config.h"

#include <glib.h>
#include "crc6.h"


guint16 update_crc6_by_bytes(guint16 crc6, guint8 byte1, guint8 byte2) {
    int bit;
    guint32 remainder = ( byte1<<8 | byte2 ) << 6;
    guint32 polynomial = 0x6F << 15;
	
    for (bit = 15;
		 bit >= 0;
		 --bit)
    {
        if (remainder & (0x40 << bit))
        {
            remainder ^= polynomial;
        }
        polynomial >>= 1;
    }
	
    return (guint16)(remainder ^ crc6);
}



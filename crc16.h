/* crc16.h
 * Declaration of CRC-16 routines and table
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@xxxxxxxxxxxx>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

/* Calculate the CCITT/ITU/CRC-16 16-bit CRC
   
   (parameters for this CRC are:
       Polynomial: x^16 + x^12 + x^5 + 1  (0x1021);
       Start value 0xFFFF;
       XOR result with 0xFFFF;
       First bit is LSB)
*/
extern guint16 crc16_ccitt(const unsigned char *buf, guint len);
extern guint16 crc16_ccitt_tvb(tvbuff_t *tvb, unsigned int len);


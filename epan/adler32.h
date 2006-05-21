/* adler32.h
 * Compute the Adler32 checksum (RFC 1950)
 * 2003 Tomas Kukosa
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

#ifndef ADLER32_H
#define ADLER32_H

#ifdef __cplusplus
extern "C"{
#endif

unsigned long update_adler32(unsigned long adler, const unsigned char *buf, int len);
unsigned long adler32_bytes(const unsigned char *buf, int len);
unsigned long adler32_str(const char *buf);

#ifdef __cplusplus
}
#endif

#endif  /* ADLER32_H */


/* adler32.c
 * Compute the Adler32 checksum (RFC 1950)
 * 2003 Tomas Kukosa
 * Based on code from RFC 1950 (Chapter 9. Appendix: Sample code)
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

#include <string.h>

#include <epan/adler32.h>

#define BASE 65521 /* largest prime smaller than 65536 */

/*--- update_adler32 --------------------------------------------------------*/
unsigned long update_adler32(unsigned long adler, const unsigned char *buf, int len)
{
  unsigned long s1 = adler & 0xffff;
  unsigned long s2 = (adler >> 16) & 0xffff;
  int n;

  for (n = 0; n < len; n++) {
    s1 = (s1 + buf[n]) % BASE;
    s2 = (s2 + s1)     % BASE;
  }
  return (s2 << 16) + s1;
}

/*--- adler32 ---------------------------------------------------------------*/
unsigned long adler32_bytes(const unsigned char *buf, int len)
{
  return update_adler32(1L, buf, len);
}

/*--- adler32_str -----------------------------------------------------------*/
unsigned long adler32_str(const char *buf)
{
  return update_adler32(1L, (const unsigned char*)buf, strlen(buf));
}

/*---------------------------------------------------------------------------*/

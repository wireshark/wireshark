/* adler32.c
 * Compute the Adler32 checksum (RFC 1950)
 * 2003 Tomas Kukosa
 * Based on code from RFC 1950 (Chapter 9. Appendix: Sample code)
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

#include <string.h>

#include <glib.h>

#include <wsutil/adler32.h>

#define BASE 65521 /* largest prime smaller than 65536 */

/*--- update_adler32 --------------------------------------------------------*/
guint32 update_adler32(guint32 adler, const guint8 *buf, size_t len)
{
  guint32 s1 = adler & 0xffff;
  guint32 s2 = (adler >> 16) & 0xffff;
  size_t n;

  for (n = 0; n < len; n++) {
    s1 = (s1 + buf[n]) % BASE;
    s2 = (s2 + s1)     % BASE;
  }
  return (s2 << 16) + s1;
}

/*--- adler32 ---------------------------------------------------------------*/
guint32 adler32_bytes(const guint8 *buf, size_t len)
{
  return update_adler32(1, buf, len);
}

/*--- adler32_str -----------------------------------------------------------*/
guint32 adler32_str(const char *buf)
{
  return update_adler32(1, (const guint8*)buf, strlen(buf));
}

/*---------------------------------------------------------------------------*/

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

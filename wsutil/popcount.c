/* popcount.c
 *
 * popcount() replacement function for systems that don't provide their own.
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

#include "wsutil/popcount.h"

int
popcount(unsigned int mask)
{
#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
      /* GCC 3.4 or newer */
      return __builtin_popcount(mask);
#else
      /* HACKMEM 169 */
      unsigned long y;

      y = (mask >> 1) &033333333333;
      y = mask - y - ((y >>1) & 033333333333);
      return (((y + (y >> 3)) & 030707070707) % 077);
#endif
}

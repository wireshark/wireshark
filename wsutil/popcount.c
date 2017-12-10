/* popcount.c
 *
 * popcount() replacement function for systems that don't provide their own.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
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

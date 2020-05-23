/* airpcap_debug.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_DEBUG_H
#define	_DOT11DECRYPT_DEBUG_H

#include "dot11decrypt_interop.h"

/* #define DOT11DECRYPT_DEBUG 1 */

/* Debug level definition */
#define DEBUG_LEVEL_1 1
#define DEBUG_LEVEL_2 2
#define DEBUG_LEVEL_3 3
#define DEBUG_LEVEL_4 4
#define DEBUG_LEVEL_5 5

#define DEBUG_USED_LEVEL DEBUG_LEVEL_3

/******************************************************************************/
/* Debug section: internal function to print debug information						*/
/*																										*/
#ifdef DOT11DECRYPT_DEBUG
#include <stdio.h>
#include <time.h>

#include <epan/to_str.h>

static inline void print_debug_line(const CHAR *function, const CHAR *msg, const INT level)
{
    if (level <= DEBUG_USED_LEVEL)
        g_warning("dbg(%d)|(%s) %s", level, function, msg);
}

#define DEBUG_PRINT_LINE(msg, level) print_debug_line(G_STRFUNC , msg, level)

static inline void DEBUG_DUMP(const char* x, const guint8* y, int z)
{
    char* tmp_str = bytes_to_str(NULL, y, (z));
    g_warning("%s: %s", x, tmp_str);
    wmem_free(NULL, tmp_str);
}

#else	/* !defined DOT11DECRYPT_DEBUG	*/

#define DEBUG_PRINT_LINE(msg, level)
#define DEBUG_DUMP(x,y,z)

#endif	/* ?defined DOT11DECRYPT_DEBUG	*/


#endif	/* ?defined _DOT11DECRYPT_DEBUG_H	*/

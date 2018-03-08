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

#ifdef DOT11DECRYPT_DEBUG
#ifdef	__FUNCTION__
#define	DOT11DECRYPT_DEBUG_PRINT_LINE(notdefined, msg, level) print_debug_line(__FUNCTION__, msg, level);
#else
#define	DOT11DECRYPT_DEBUG_PRINT_LINE(function, msg, level) print_debug_line(function, msg, level);
#endif
#else
#ifdef	__FUNCTION__
#define	DOT11DECRYPT_DEBUG_PRINT_LINE(notdefined, msg, level)
#else
#define	DOT11DECRYPT_DEBUG_PRINT_LINE(function, msg, level)
#endif
#endif

/******************************************************************************/
/* Debug section: internal function to print debug information						*/
/*																										*/
#ifdef DOT11DECRYPT_DEBUG
#include <stdio.h>
#include <time.h>

#include <epan/to_str.h>

/*	Debug level definition																		*/
#define	DOT11DECRYPT_DEBUG_LEVEL_1	1
#define	DOT11DECRYPT_DEBUG_LEVEL_2	2
#define	DOT11DECRYPT_DEBUG_LEVEL_3	3
#define	DOT11DECRYPT_DEBUG_LEVEL_4	4
#define	DOT11DECRYPT_DEBUG_LEVEL_5	5

#define	DOT11DECRYPT_DEBUG_USED_LEVEL	DOT11DECRYPT_DEBUG_LEVEL_3

static inline void print_debug_line(const CHAR *function, const CHAR *msg, const INT level)
{
    if (level<=DOT11DECRYPT_DEBUG_USED_LEVEL)
        g_warning("dbg(%d)|(%s) %s", level, function, msg);
}

#ifdef	_TRACE
#ifdef	__FUNCTION__
#define	DOT11DECRYPT_DEBUG_TRACE_START(notdefined) print_debug_line(__FUNCTION__, "Start!", DOT11DECRYPT_DEBUG_USED_LEVEL);
#define	DOT11DECRYPT_DEBUG_TRACE_END(notdefined) print_debug_line(__FUNCTION__, "End!", DOT11DECRYPT_DEBUG_USED_LEVEL);
#else
#define	DOT11DECRYPT_DEBUG_TRACE_START(function) print_debug_line(function, "Start!", DOT11DECRYPT_DEBUG_USED_LEVEL);
#define	DOT11DECRYPT_DEBUG_TRACE_END(function) print_debug_line(function, "End!", DOT11DECRYPT_DEBUG_USED_LEVEL);
#endif
#else
#ifdef	__FUNCTION__
#define	DOT11DECRYPT_DEBUG_TRACE_START(notdefined)
#define	DOT11DECRYPT_DEBUG_TRACE_END(notdefined)
#else
#define	DOT11DECRYPT_DEBUG_TRACE_START(function)
#define	DOT11DECRYPT_DEBUG_TRACE_END(function)
#endif
#endif

static inline void DEBUG_DUMP(const char* x, const guint8* y, int z)
{
    char* tmp_str = bytes_to_str(NULL, y, (z));
    g_warning("%s: %s", x, tmp_str);
    wmem_free(NULL, tmp_str);
}

#else	/* !defined DOT11DECRYPT_DEBUG	*/

#define	DOT11DECRYPT_DEBUG_LEVEL_1
#define	DOT11DECRYPT_DEBUG_LEVEL_2
#define	DOT11DECRYPT_DEBUG_LEVEL_3
#define	DOT11DECRYPT_DEBUG_LEVEL_4
#define	DOT11DECRYPT_DEBUG_LEVEL_5

#define	DOT11DECRYPT_DEBUG_TRACE_START(function)
#define	DOT11DECRYPT_DEBUG_TRACE_END(function)

#define DEBUG_DUMP(x,y,z)

#endif	/* ?defined DOT11DECRYPT_DEBUG	*/


#endif	/* ?defined _DOT11DECRYPT_DEBUG_H	*/

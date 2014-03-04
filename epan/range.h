/* range.h
 * Range routines
 *
 * Dick Gooris <gooris@lucent.com>
 * Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __RANGE_H__
#define __RANGE_H__

#include <glib.h>
#include "ws_symbol_export.h"

/** @file
 * Range strings a variant of value_strings
 */

/**@todo where's the best place for these? */
#define MAX_SCTP_PORT 65535
#define MAX_TCP_PORT 65535
#define MAX_UDP_PORT 65535
#define MAX_DCCP_PORT 65535

typedef struct range_admin_tag {
    guint32 low;
    guint32 high;
} range_admin_t;

/** user specified range(s) */
typedef struct epan_range {
    guint           nranges;   /**< number of entries in ranges */
    range_admin_t   ranges[1]; /**< variable-length array */
} range_t;

/**
 * Return value from range_convert_str().
 */
typedef enum {
    CVT_NO_ERROR,
    CVT_SYNTAX_ERROR,
    CVT_NUMBER_TOO_BIG
} convert_ret_t;

WS_DLL_PUBLIC range_t *range_empty(void);


/*** Converts a range string to a fast comparable array of ranges.
 * This function allocates a range_t large enough to hold the number
 * of ranges specified, and fills the array range->ranges containing
 * low and high values with the number of ranges being range->nranges.
 * After having called this function, the function value_is_in_range()
 * determines whether a given number is within the range or not.<BR>
 * In case of a single number, we make a range where low is equal to high.
 * We take care on wrongly entered ranges; opposite order will be taken
 * care of.
 *
 * The following syntax is accepted :
 *
 *   1-20,30-40     Range from 1 to 20, and packets 30 to 40
 *   -20,30         Range from 1 to 20, and packet 30
 *   20,30,40-      20, 30, and the range from 40 to the end
 *   20-10,30-25    Range from 10 to 20, and from 25 to 30
 *   -              All values
 * @param range the range
 * @param es points to the string to be converted.
 * @param max_value specifies the maximum value in a range.
 * @return convert_ret_t
 */
WS_DLL_PUBLIC convert_ret_t range_convert_str(range_t **range, const gchar *es,
    guint32 max_value);

convert_ret_t range_convert_str_work(range_t **range, const gchar *es,
    guint32 max_value, gboolean err_on_max);

/** This function returns TRUE if a given value is within one of the ranges
 * stored in the ranges array.
 * @param range the range
 * @param val the value to check
 * @return TRUE if the value is in range
 */
WS_DLL_PUBLIC gboolean value_is_in_range(range_t *range, guint32 val);

/** This function returns TRUE if the two given range_t's are equal.
 * @param a first range
 * @param b second range
 * @return TRUE if the value is in range
 */
WS_DLL_PUBLIC gboolean ranges_are_equal(range_t *a, range_t *b);

/** This function calls the provided callback function for each value in
 * in the range.
 * @param range the range
 * @param callback the callback function
 */
WS_DLL_PUBLIC void range_foreach(range_t *range, void (*callback)(guint32 val));

/**
 * This function converts a range_t to a (ep_alloc()-allocated) string.
 */
WS_DLL_PUBLIC char *range_convert_range(range_t *range);

/**
 * Create a copy of a range.
 * @param src the range to copy
 * @return ep allocated copy of the range
 */
WS_DLL_PUBLIC range_t *range_copy(range_t *src);

#endif /* __RANGE_H__ */

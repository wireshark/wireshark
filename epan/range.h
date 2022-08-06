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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RANGE_H__
#define __RANGE_H__

#include <glib.h>
#include "ws_symbol_export.h"
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
#define RANGE_ADMIN_T_INITIALIZER { 0, 0 }

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

WS_DLL_PUBLIC range_t *range_empty(wmem_allocator_t *scope);


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
 * @param scope memory scope for the range
 * @param range the range
 * @param es points to the string to be converted.
 * @param max_value specifies the maximum value in a range.
 * @return convert_ret_t
 */
WS_DLL_PUBLIC convert_ret_t range_convert_str(wmem_allocator_t *scope, range_t **range, const gchar *es,
    guint32 max_value);

WS_DLL_PUBLIC convert_ret_t range_convert_str_work(wmem_allocator_t *scope, range_t **range, const gchar *es,
    guint32 max_value, gboolean err_on_max);

/** This function returns TRUE if a given value is within one of the ranges
 * stored in the ranges array.
 * @param range the range
 * @param val the value to check
 * @return TRUE if the value is in range
 */
WS_DLL_PUBLIC gboolean value_is_in_range(const range_t *range, guint32 val);

/** This function returns TRUE if val has successfully been added to
 * a range.  This may extend an existing range or create a new one
 * @param scope memory scope of range (in case of reallocation)
 * @param range to add value
 * @param val value to add to range
 * @return TRUE if the value is successsfully added to range
 */
WS_DLL_PUBLIC gboolean range_add_value(wmem_allocator_t *scope, range_t **range, guint32 val);

/** This function returns TRUE if val has successfully been removed from
 * a range.  This may remove an existing range.
 * @param scope memory scope of range (in case of reallocation)
 * @param range to remove value
 * @param val value to remove within range
 * @return TRUE if the value is successsfully removed to range
 */
WS_DLL_PUBLIC gboolean range_remove_value(wmem_allocator_t *scope, range_t **range, guint32 val);

/** This function returns TRUE if the two given range_t's are equal.
 * @param a first range
 * @param b second range
 * @return TRUE if the value is in range
 */
WS_DLL_PUBLIC gboolean ranges_are_equal(const range_t *a, const range_t *b);

/** This function calls the provided callback function for each value in
 * in the range. Takes a pointer argument, which is passed to the
 * callback, along with the value in the range.
 * @param range the range
 * @param callback the callback function
 * @param ptr pointer passed to the callback
 */
WS_DLL_PUBLIC void range_foreach(range_t *range, void (*callback)(guint32 val, gpointer ptr), gpointer ptr);

/**
 * This function converts a range_t to a (wmem_alloc()-allocated) string.
 */
WS_DLL_PUBLIC char *range_convert_range(wmem_allocator_t *scope, const range_t *range);

/**
 * Create a (wmem-alloc()ed) copy of a range
 * @param scope memory scope for the copied range
 * @param src the range to copy
 * @return ep allocated copy of the range
 */
WS_DLL_PUBLIC range_t *range_copy(wmem_allocator_t *scope, const range_t *src);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RANGE_H__ */

/* column-utils.h
 * Definitions for column utility structures and routines
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

#ifndef __COLUMN_UTILS_H__
#define __COLUMN_UTILS_H__

#include <glib.h>

#include "gnuc_format_check.h"
#include "column_info.h"
#include "packet_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Maximum length of columns (except COL_INFO).
 * Internal, don't use this in dissectors!
 */

#define COL_MAX_LEN 256
/** Maximum length of info columns (COL_INFO only).
 * Internal, don't use this in dissectors!
 */
#define COL_MAX_INFO_LEN 4096


/** Allocate all the data structures for constructing column data, given
 * the number of columns.
 *
 * Internal, don't use this in dissectors!
 */
extern void	col_setup(column_info *cinfo, gint num_cols);

/** Initialize the data structures for constructing column data.
 *
 * Internal, don't use this in dissectors!
 */
extern void	col_init(column_info *cinfo);

/** Set the format of the "variable time format".
 *
 * Internal, don't use this in dissectors!
 */
extern void	col_set_cls_time(frame_data *, column_info *cinfo, gint col);

/** Fill in all columns of the given packet.
 *
 * Internal, don't use this in dissectors!
 */
extern void	col_fill_in(packet_info *pinfo);

/* Utility routines used by packet*.c */

/** Are the columns writable?
 *
 * @param cinfo the current packet row
 * @return TRUE if it's writable, FALSE if not
 */
extern gboolean	col_get_writable(column_info *cinfo);

/** Set the columns writable. 
 *
 * @param cinfo the current packet row
 * @param writable TRUE if it's writable, FALSE if not
 */
extern void	col_set_writable(column_info *cinfo, gboolean writable);

/** Check if the given column be filled with data.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
extern gint	check_col(column_info *cinfo, gint col);

/** Sets a fence for the current column content, 
 * so this content won't be affected by further col_... function calls. 
 *
 * This can be useful if a protocol is more than once in a single packet,
 * e.g. multiple HTTP calls in a single TCP packet.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
extern void	col_set_fence(column_info *cinfo, gint col);

/** Clears the text of a column element.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
extern void	col_clear(column_info *cinfo, gint col);

/** Set (replace) the text of a column element, the text won't be copied.
 *
 * Usually used to set const strings!
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to set
 */
extern void	col_set_str(column_info *cinfo, gint col, const gchar * str);

/** Add (replace) the text of a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to add
 */
extern void	col_add_str(column_info *cinfo, gint col, const gchar *str);

/** Add (replace) the text of a column element, the text will be formatted and copied.
 *
 * Same function as col_add_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
extern void	col_add_fstr(column_info *cinfo, gint col, const gchar *format, ...)
    GNUC_FORMAT_CHECK(printf, 3, 4);

/** Append the given text to a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to append
 */
extern void	col_append_str(column_info *cinfo, gint col, const gchar *str);

/** Append the given text to a column element, the text will be formatted and copied.
 *
 * Same function as col_append_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
extern void	col_append_fstr(column_info *cinfo, gint col, const gchar *format, ...)
    GNUC_FORMAT_CHECK(printf, 3, 4);

/** Prepend the given text to a column element, the text will be formatted and copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
extern void	col_prepend_fstr(column_info *cinfo, gint col, const gchar *format, ...)
    GNUC_FORMAT_CHECK(printf, 3, 4);

/**Prepend the given text to a column element, the text will be formatted and copied.
 * This function is similar to col_prepend_fstr() but this function will
 * unconditionally set a fence to the end of the prepended data even if there
 * were no fence before.
 * The col_prepend_fstr() will only prepend the data before the fence IFF
 * there is already a fence created. This function will create a fence in case
 * it does not yet exist.
 */
extern void	col_prepend_fence_fstr(column_info *cinfo, gint col, const gchar *format, ...)
    GNUC_FORMAT_CHECK(printf, 3, 4);

/** Append the given text (prepended by a separator) to a column element.
 *
 * Much like col_append_str() but will prepend the given separator if the column isn't empty.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param sep the separator string or NULL for default: ", "
 * @param str the string to append
 */
extern void	col_append_sep_str(column_info *cinfo, gint col, const gchar *sep,
		const gchar *str);

/** Append the given text (prepended by a separator) to a column element.
 *
 * Much like col_append_fstr() but will prepend the given separator if the column isn't empty.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param sep the separator string or NULL for default: ", "
 * @param format the format string
 * @param ... the variable number of parameters
 */
extern void	col_append_sep_fstr(column_info *cinfo, gint col, const gchar *sep,
		const gchar *format, ...)
    GNUC_FORMAT_CHECK(printf, 4, 5);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_UTILS_H__ */

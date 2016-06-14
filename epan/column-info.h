/* column-info.h
 * Definitions for column structures and routines
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

#ifndef __COLUMN_INFO_H__
#define __COLUMN_INFO_H__

#include <glib.h>
#include <epan/column-utils.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Column info.
 */

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096
#define COL_CUSTOM_PRIME_REGEX " *([^ \\|]+) *(?:(?:\\|\\|)|(?:or)| *$){1}"

/** Column expression */
typedef struct {
  const gchar **col_expr;     /**< Filter expression */
  gchar      **col_expr_val;  /**< Value for filter expression */
} col_expr_t;

/** Individual column info */
typedef struct {
  gint                col_fmt;              /**< Format of column */
  gboolean           *fmt_matx;             /**< Specifies which formats apply to a column */
  gchar              *col_title;            /**< Column titles */
  gchar              *col_custom_fields;    /**< Custom column fields */
  gint                col_custom_occurrence;/**< Custom column field occurrence */
  GSList             *col_custom_fields_ids;/**< Custom column fields id */
  struct epan_dfilter *col_custom_dfilter;  /**< Compiled custom column field */
  const gchar        *col_data;             /**< Column data */
  gchar              *col_buf;              /**< Buffer into which to copy data for column */
  int                 col_fence;            /**< Stuff in column buffer before this index is immutable */
  gboolean            writable;             /**< writable or not */
} col_item_t;

/** Column info */
struct epan_column_info {
  const struct epan_session *epan;
  gint                num_cols;             /**< Number of columns */
  col_item_t         *columns;              /**< All column data */
  gint               *col_first;            /**< First column number with a given format */
  gint               *col_last;             /**< Last column number with a given format */
  col_expr_t          col_expr;             /**< Column expressions and values */
  gboolean            writable;             /**< writable or not @todo Are we still writing to the columns? */
  GRegex             *prime_regex;          /**< Used to prime custom columns */
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_INFO_H__ */

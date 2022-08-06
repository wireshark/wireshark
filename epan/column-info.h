/* column-info.h
 * Definitions for internal column structures and routines
 *
 * For internal Wireshark use only. Don't include this header in dissectors!
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/** Allocate all the data structures for constructing column data, given
 * the number of columns.
 */
WS_DLL_PUBLIC void col_setup(column_info *cinfo, const gint num_cols);

/** Cleanup all the data structures for constructing column data;
 * undoes the alocations that col_setup() does.
 */
WS_DLL_PUBLIC void col_cleanup(column_info *cinfo);

/** Initialize the data structures for constructing column data.
 */
extern void col_init(column_info *cinfo, const struct epan_session *epan);

/** Fill in all columns of the given packet which are based on values from frame_data.
 */
WS_DLL_PUBLIC void col_fill_in_frame_data(const frame_data *fd, column_info *cinfo, const gint col, gboolean const fill_col_exprs);

/** Fill in all columns of the given packet.
 */
WS_DLL_PUBLIC void col_fill_in(packet_info *pinfo, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Fill in columns if we got an error reading the packet.
 * We set most columns to "???", and set the Info column to an error
 * message.
 */
WS_DLL_PUBLIC void col_fill_in_error(column_info *cinfo, frame_data *fdata, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Check to see if our column data has changed, e.g. we have new request/response info.
 */
WS_DLL_PUBLIC gboolean  col_data_changed(void);

void col_custom_set_edt(struct epan_dissect *edt, column_info *cinfo);

WS_DLL_PUBLIC
void col_custom_prime_edt(struct epan_dissect *edt, column_info *cinfo);

WS_DLL_PUBLIC
gboolean have_custom_cols(column_info *cinfo);

WS_DLL_PUBLIC
gboolean have_field_extractors(void);

WS_DLL_PUBLIC
gboolean col_has_time_fmt(column_info *cinfo, const gint col);

WS_DLL_PUBLIC
gboolean col_based_on_frame_data(column_info *cinfo, const gint col);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_INFO_H__ */

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
#pragma once
#include <epan/column-utils.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Column info.
 */

typedef struct _proto_node proto_tree;

#define COLUMN_FIELD_FILTER  "_ws.col."

/** Column expression */
typedef struct {
  const char **col_expr;      /**< Filter expression */
  char       **col_expr_val;  /**< Value for filter expression */
} col_expr_t;

/** Custom column filter expression information used in the GSList below.
 * One for each expression in a multifield column.
 */
typedef struct {
  char                *dftext;         /**< Filter expression */
  struct epan_dfilter *dfilter;        /**< Compiled filter expression */
  int                  field_id;       /**< ID for a single field expression, or 0 */
} col_custom_t;

/** Individual column info */
typedef struct {
  int                 col_fmt;              /**< Format of column */
  bool               *fmt_matx;             /**< Specifies which formats apply to a column */
  char               *col_title;            /**< Column titles */
  char               *col_custom_fields;    /**< Custom column fields */
  int                 col_custom_occurrence;/**< Custom column field occurrence */
  GSList             *col_custom_fields_ids;/**< Custom column fields id */
  struct epan_dfilter *col_custom_dfilter;  /**< Compiled custom column field */
  const char         *col_data;             /**< Column data */
  char               *col_buf;              /**< Buffer into which to copy data for column */
  int                 col_fence;            /**< Stuff in column buffer before this index is immutable */
  bool                writable;             /**< writable or not */
  int                 hf_id;
} col_item_t;

/** Column info */
struct epan_column_info {
  const struct epan_session *epan;
  unsigned            num_cols;             /**< Number of columns */
  col_item_t         *columns;              /**< All column data */
  int                *col_first;            /**< First column number with a given format */
  int                *col_last;             /**< Last column number with a given format */
  col_expr_t          col_expr;             /**< Column expressions and values */
  bool                writable;             /**< writable or not @todo Are we still writing to the columns? */
  GRegex             *prime_regex;          /**< Used to prime custom columns */
};

/**
 * @brief Allocate and initialize column‑handling structures.
 *
 * Prepares a column_info structure for use by the column subsystem by
 * allocating the internal data structures required to
 * store, format, and update column values during dissection.
 *
 * @param cinfo     The column_info structure to initialize.
 * @param num_cols  The number of columns to allocate space for.
 */
WS_DLL_PUBLIC void col_setup(column_info *cinfo, const int num_cols);

/**
 * @brief Release all column‑handling data structures.
 *
 * Cleanup all the data structures for constructing column data;
 * undoes the allocations that col_setup() does.
 * @param cinfo  The column_info structure whose resources should be freed.
 */
WS_DLL_PUBLIC void col_cleanup(column_info *cinfo);

/**
 * @brief Initialize the data structures for constructing column data.
 *
 * @param cinfo  The column_info structure to initialize.
 * @param epan   The epan_session providing context and preferences.
 */
extern void col_init(column_info *cinfo, const struct epan_session *epan);

/** Fill in all columns of the given packet which are based on values from frame_data.
 */
WS_DLL_PUBLIC void col_fill_in_frame_data(const frame_data *fd, column_info *cinfo, const int col, bool const fill_col_exprs);

/** Fill in all (non-custom) columns of the given packet.
 */
WS_DLL_PUBLIC void col_fill_in(packet_info *pinfo, const bool fill_col_exprs, const bool fill_fd_colums);

/** Fill in columns if we got an error reading the packet.
 * We set most columns to "???", and set the Info column to an error
 * message.
 */
WS_DLL_PUBLIC void col_fill_in_error(column_info *cinfo, frame_data *fdata, const bool fill_col_exprs, const bool fill_fd_colums);

/** Check to see if our column data has changed, e.g. we have new request/response info.
 */
WS_DLL_PUBLIC bool      col_data_changed(void);

/**
 * @brief Set custom data type for a column in an epan_dissect structure.
 *
 * This function updates the custom data type for each custom column in the provided column_info structure.
 *
 * @param edt Pointer to the epan_dissect structure containing the dissector information.
 * @param cinfo Pointer to the column_info structure containing the column information.
 */
void col_custom_set_edt(struct epan_dissect *edt, column_info *cinfo);

/**
 * @brief Prime custom columns in an epan_dissect structure.
 *
 * @param edt Pointer to the epan_dissect structure containing the dissector information.
 * @param cinfo Pointer to the column_info structure containing the column information.
 */
WS_DLL_PUBLIC
void col_custom_prime_edt(struct epan_dissect *edt, column_info *cinfo);

/** Get a filter expression for a custom column. This string must be g_free'd.
 */
WS_DLL_PUBLIC
char* col_custom_get_filter(struct epan_dissect *edt, column_info *cinfo, const unsigned col);

/**
 * @brief Checks if there are custom columns in the given column_info structure.
 *
 * @param cinfo Pointer to the column_info structure to check.
 * @return true if there are custom columns, false otherwise.
 */
WS_DLL_PUBLIC
bool have_custom_cols(column_info *cinfo);

/**
 * @brief Checks if field extractors are available.
 *
 * @return true if field extractors are available, false otherwise.
 */
WS_DLL_PUBLIC
bool have_field_extractors(void);

/**
 * @brief Check if a column has any time format.
 *
 * @param cinfo Pointer to the column information structure.
 * @param col Column index to check.
 * @return true If the column has any time format, false otherwise.
 */
WS_DLL_PUBLIC
bool col_has_time_fmt(column_info *cinfo, const unsigned col);

/**
 * @brief Determines if a column is based on frame data.
 *
 * @param cinfo Pointer to the column information structure.
 * @param col Column index.
 * @return true If the column is based on frame data, false otherwise.
 */
WS_DLL_PUBLIC
bool col_based_on_frame_data(column_info *cinfo, const unsigned col);

/**
 * @brief Registers the protocol columns for Wireshark.
 *
 * This function initializes and registers the protocol columns used in Wireshark's packet display.
 */
void
col_register_protocol(void);

/**
 * @brief Dissects and populates columns in a packet display tree.
 *
 * This function processes a tvbuff_t containing packet data, extracts relevant information,
 * and populates the specified proto_tree with column data based on the packet's protocol and content.
 *
 * @param tvb Pointer to the tvbuff_t containing the packet data.
 * @param pinfo Pointer to the packet_info structure containing metadata about the packet.
 * @param tree Pointer to the proto_tree where column data will be added.
 */
extern
void col_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#ifdef __cplusplus
}
#endif /* __cplusplus */

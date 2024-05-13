/** @file
 * Definitions for column utility structures and routines
 * Utility routines used by packet*.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COLUMN_UTILS_H__
#define __COLUMN_UTILS_H__

#include <glib.h>

#include "packet_info.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define COL_MAX_LEN 2048
#define COL_MAX_INFO_LEN 4096

/* A regex to split possibly multifield custom columns into components
 *
 * Split on operator "||" (with optional space around it) and on "or"
 * (which must have space around it to avoid matching in the middle of
 * a word, field in the "synphasor" protocol, etc. This is somewhat too
 * strict, as "or" adjacent to parentheses ought to be fine so long
 * as the filter matches the grammar, like "(tcp.port)or(udp.port)",
 * but that's the cost of using regex instead of the real parser.)
 * Also split on space at the beginning or end of the expression (in
 * lieu of always stripping whitespace at the beginning and end, but it
 * does mean that we have to ignore any empty tokens in the result.)
 *
 * Use negative lookahead to avoid matching "||" or "or" that are contained
 * within parentheses. Don't match if a close parenthesis comes before an
 * open parenthesis. The regex doesn't help with unmatched parentheses, but
 * such an expression already won't satisfy the grammar and won't compile.
 */
#define COL_CUSTOM_PRIME_REGEX "(?:^ *| *\\|\\| *| +or +| *$)(?![^(]*\\))"

struct epan_dissect;

/**
 *  Helper routines for column utility structures and routines.
 */

struct epan_column_info;
typedef struct epan_column_info column_info;

/**
 * All of the possible columns in summary listing.
 *
 * NOTE1: The entries MUST remain in this order, or else you need to reorder
 *        the slist[] and dlist[] arrays in column.c to match!
 *
 * NOTE2: Please add the COL_XYZ entry in the appropriate spot, such that the
 *        dlist[] array remains in alphabetical order!
 */
enum {
  COL_ABS_YMD_TIME,   /**< 0) Absolute date, as YYYY-MM-DD, and time */
  COL_ABS_YDOY_TIME,  /**< 1) Absolute date, as YYYY/DOY, and time */
  COL_ABS_TIME,       /**< 2) Absolute time */
  COL_CUMULATIVE_BYTES, /**< 3) Cumulative number of bytes */
  COL_CUSTOM,         /**< 4) Custom column (any filter name's contents) */
  COL_DELTA_TIME,     /**< 5) Delta time */
  COL_DELTA_TIME_DIS, /**< 6) Delta time displayed*/
  COL_RES_DST,        /**< 7) Resolved dest */
  COL_UNRES_DST,      /**< 8) Unresolved dest */
  COL_RES_DST_PORT,   /**< 9) Resolved dest port */
  COL_UNRES_DST_PORT, /**< 10) Unresolved dest port */
  COL_DEF_DST,        /**< 11) Destination address */
  COL_DEF_DST_PORT,   /**< 12) Destination port */
  COL_EXPERT,         /**< 13) Expert Info */
  COL_IF_DIR,         /**< 14) FW-1 monitor interface/direction */
  COL_FREQ_CHAN,      /**< 15) IEEE 802.11 (and WiMax?) - Channel */
  COL_DEF_DL_DST,     /**< 16) Data link layer dest address */
  COL_DEF_DL_SRC,     /**< 17) Data link layer source address */
  COL_RES_DL_DST,     /**< 18) Resolved DL dest */
  COL_UNRES_DL_DST,   /**< 19) Unresolved DL dest */
  COL_RES_DL_SRC,     /**< 20) Resolved DL source */
  COL_UNRES_DL_SRC,   /**< 21) Unresolved DL source */
  COL_RSSI,           /**< 22) IEEE 802.11 - received signal strength */
  COL_TX_RATE,        /**< 23) IEEE 802.11 - TX rate in Mbps */
  COL_DSCP_VALUE,     /**< 24) IP DSCP Value */
  COL_INFO,           /**< 25) Description */
  COL_RES_NET_DST,    /**< 26) Resolved net dest */
  COL_UNRES_NET_DST,  /**< 27) Unresolved net dest */
  COL_RES_NET_SRC,    /**< 28) Resolved net source */
  COL_UNRES_NET_SRC,  /**< 29) Unresolved net source */
  COL_DEF_NET_DST,    /**< 30) Network layer dest address */
  COL_DEF_NET_SRC,    /**< 31) Network layer source address */
  COL_NUMBER,         /**< 32) Packet list item number */
  COL_PACKET_LENGTH,  /**< 33) Packet length in bytes */
  COL_PROTOCOL,       /**< 34) Protocol */
  COL_REL_TIME,       /**< 35) Relative time */
  COL_DEF_SRC,        /**< 36) Source address */
  COL_DEF_SRC_PORT,   /**< 37) Source port */
  COL_RES_SRC,        /**< 38) Resolved source */
  COL_UNRES_SRC,      /**< 39) Unresolved source */
  COL_RES_SRC_PORT,   /**< 40) Resolved source port */
  COL_UNRES_SRC_PORT, /**< 41) Unresolved source port */
  COL_UTC_YMD_TIME,   /**< 42) UTC date, as YYYY-MM-DD, and time */
  COL_UTC_YDOY_TIME,  /**< 43) UTC date, as YYYY/DOY, and time */
  COL_UTC_TIME,       /**< 44) UTC time */
  COL_CLS_TIME,       /**< 45) Command line-specified time (default relative) */
  NUM_COL_FMTS        /**< 46) Should always be last */
};

/** Are the columns writable?
 *
 * @param cinfo the current packet row
 * @param col the writable column, -1 for checking the state of all columns
 * @return true if it's writable, false if not
 */
WS_DLL_PUBLIC bool col_get_writable(column_info *cinfo, const int col);

/** Set the columns writable.
 *
 * @param cinfo the current packet row
 * @param col the column to set, -1 for all
 * @param writable true if it's writable, false if not
 */
WS_DLL_PUBLIC void col_set_writable(column_info *cinfo, const int col, const bool writable);

/** Sets a fence for the current column content,
 * so this content won't be affected by further col_... function calls.
 *
 * This can be useful if a protocol is more than once in a single packet,
 * e.g. multiple HTTP calls in a single TCP packet.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void col_set_fence(column_info *cinfo, const int col);

/** Clears a fence for the current column content
 *
 * This can be useful if a protocol wants to remove whatever
 * a previous protocol has added to the column.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void col_clear_fence(column_info *cinfo, const int col);

/** Gets the text of a column element.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 *
 * @return the text string
 */
WS_DLL_PUBLIC const char *col_get_text(column_info *cinfo, const int col);

/** Clears the text of a column element.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void col_clear(column_info *cinfo, const int col);

/** Set (replace) the text of a column element, the text won't be formatted or copied.
 *
 * Use this for simple static strings like protocol names. Don't use for untrusted strings
 * or strings that may contain unprintable characters.
 *
 * Usually used to set const strings!
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to set
 */
WS_DLL_PUBLIC void col_set_str(column_info *cinfo, const int col, const char * str);

/** Add (replace) the text of a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to add
 */
WS_DLL_PUBLIC void col_add_str(column_info *cinfo, const int col, const char *str);

/* terminator argument for col_add_lstr() function */
#define COL_ADD_LSTR_TERMINATOR (const char *) -1

WS_DLL_PUBLIC void col_add_lstr(column_info *cinfo, const int el, const char *str, ...);

/** Add (replace) the text of a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * Same function as col_add_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void col_add_fstr(column_info *cinfo, const int col, const char *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Append the given text to a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to append
 */
WS_DLL_PUBLIC void col_append_str(column_info *cinfo, const int col, const char *str);

/** Append <abbrev>=<val> to a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param abbrev the string to append
 * @param val the value to append
 * @param sep an optional separator to _prepend_ to abbrev
 */
WS_DLL_PUBLIC void col_append_str_uint(column_info *cinfo, const int col, const char *abbrev, uint32_t val, const char *sep);

/** Append a transport port pair to a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param typ the port type to resolve, e.g. PT_UDP
 * @param src the source port value to append
 * @param dst the destination port value to append
 */
WS_DLL_PUBLIC void col_append_ports(column_info *cinfo, const int col, port_type typ, uint16_t src, uint16_t dst);

/** Append a frame number and signal that we have updated
 * column information.
 *
 * @param pinfo the current packet info
 * @param col the column to use, e.g. COL_INFO
 * @param fmt_str format string, e.g. "reassembled in %u".
 * @param frame_num frame number
 */
WS_DLL_PUBLIC void col_append_frame_number(packet_info *pinfo, const int col, const char *fmt_str, unsigned frame_num);

/* Append the given strings (terminated by COL_ADD_LSTR_TERMINATOR) to a column element,
 *
 * Same result as col_append_str() called for every string element.
 */
WS_DLL_PUBLIC void col_append_lstr(column_info *cinfo, const int el, const char *str, ...);

/** Append the given text to a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * Same function as col_append_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void col_append_fstr(column_info *cinfo, const int col, const char *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Prepend the given text to a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void col_prepend_fstr(column_info *cinfo, const int col, const char *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Prepend the given text to a column element, the text will be formatted and copied.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * This function is similar to col_prepend_fstr() but this function will
 * unconditionally set a fence to the end of the prepended data even if there
 * were no fence before.
 * The col_prepend_fstr() will only prepend the data before the fence IF
 * there is already a fence created. This function will create a fence in case
 * it does not yet exist.
 */
WS_DLL_PUBLIC void col_prepend_fence_fstr(column_info *cinfo, const int col, const char *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Append the given text (prepended by a separator) to a column element.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * Much like col_append_str() but will prepend the given separator if the column isn't empty.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param sep the separator string or NULL for default: ", "
 * @param str the string to append
 */
WS_DLL_PUBLIC void col_append_sep_str(column_info *cinfo, const int col, const char *sep,
		const char *str);

/** Append the given text (prepended by a separator) to a column element.
 *
 * Unprintable characters according to isprint() are escaped.
 *
 * Much like col_append_fstr() but will prepend the given separator if the column isn't empty.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param sep the separator string or NULL for default: ", "
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void col_append_sep_fstr(column_info *cinfo, const int col, const char *sep,
		const char *format, ...)
    G_GNUC_PRINTF(4, 5);

/** Set the given (relative) time to a column element.
 *
 * Used by dissectors to set the time in a column
 *
 * @param cinfo		the current packet row
 * @param col		the column to use, e.g. COL_INFO
 * @param ts		the time to set in the column
 * @param fieldname	the fieldname to use for creating a filter (when
 *			  applying/preparing/copying as filter)
 */
WS_DLL_PUBLIC void col_set_time(column_info *cinfo, const int col,
			const nstime_t *ts, const char *fieldname);

WS_DLL_PUBLIC void set_fd_time(const struct epan_session *epan, frame_data *fd, char *buf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_UTILS_H__ */

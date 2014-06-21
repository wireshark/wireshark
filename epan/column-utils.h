/* column-utils.h
 * Definitions for column utility structures and routines
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

#ifndef __COLUMN_UTILS_H__
#define __COLUMN_UTILS_H__

#include <glib.h>

#include "packet_info.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct epan_dissect;

/** @file
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
  COL_8021Q_VLAN_ID,  /**< 0) 802.1Q vlan ID */
  COL_ABS_YMD_TIME,   /**< 1) Absolute date, as YYYY-MM-DD, and time */
  COL_ABS_YDOY_TIME,  /**< 2) Absolute date, as YYYY/DOY, and time */
  COL_ABS_TIME,       /**< 3) Absolute time */
  COL_CIRCUIT_ID,     /**< 4) Circuit ID */
  COL_DSTIDX,         /**< 5) !! DEPRECATED !! - Dst port idx - Cisco MDS-specific */
  COL_SRCIDX,         /**< 6) !! DEPRECATED !! - Src port idx - Cisco MDS-specific */
  COL_VSAN,           /**< 7) VSAN - Cisco MDS-specific */
  COL_CUMULATIVE_BYTES, /**< 8) Cumulative number of bytes */
  COL_CUSTOM,         /**< 9) Custom column (any filter name's contents) */
  COL_DCE_CALL,       /**< 10) DCE/RPC connection oriented call id OR datagram sequence number */
  COL_DCE_CTX,        /**< 11) !! DEPRECATED !! - DCE/RPC connection oriented context id */
  COL_DELTA_TIME,     /**< 12) Delta time */
  COL_DELTA_CONV_TIME,/**< 13) Delta time to last frame in conversation */
  COL_DELTA_TIME_DIS, /**< 14) Delta time displayed*/
  COL_RES_DST,        /**< 15) Resolved dest */
  COL_UNRES_DST,      /**< 16) Unresolved dest */
  COL_RES_DST_PORT,   /**< 17) Resolved dest port */
  COL_UNRES_DST_PORT, /**< 18) Unresolved dest port */
  COL_DEF_DST,        /**< 19) Destination address */
  COL_DEF_DST_PORT,   /**< 20) Destination port */
  COL_EXPERT,         /**< 21) Expert Info */
  COL_IF_DIR,         /**< 22) FW-1 monitor interface/direction */
  COL_OXID,           /**< 23) !! DEPRECATED !! - Fibre Channel OXID */
  COL_RXID,           /**< 24) !! DEPRECATED !! - Fibre Channel RXID */
  COL_FR_DLCI,        /**< 25) !! DEPRECATED !! - Frame Relay DLCI */
  COL_FREQ_CHAN,      /**< 26) IEEE 802.11 (and WiMax?) - Channel */
  COL_BSSGP_TLLI,     /**< 27) !! DEPRECATED !! - GPRS BSSGP IE TLLI */
  COL_HPUX_DEVID,     /**< 28) !! DEPRECATED !! - HP-UX Nettl Device ID */
  COL_HPUX_SUBSYS,    /**< 29) !! DEPRECATED !! - HP-UX Nettl Subsystem */
  COL_DEF_DL_DST,     /**< 30) Data link layer dest address */
  COL_DEF_DL_SRC,     /**< 31) Data link layer source address */
  COL_RES_DL_DST,     /**< 32) Resolved DL dest */
  COL_UNRES_DL_DST,   /**< 33) Unresolved DL dest */
  COL_RES_DL_SRC,     /**< 34) Resolved DL source */
  COL_UNRES_DL_SRC,   /**< 35) Unresolved DL source */
  COL_RSSI,           /**< 36) IEEE 802.11 - received signal strength */
  COL_TX_RATE,        /**< 37) IEEE 802.11 - TX rate in Mbps */
  COL_DSCP_VALUE,     /**< 38) IP DSCP Value */
  COL_INFO,           /**< 39) Description */
  COL_COS_VALUE,      /**< 40) !! DEPRECATED !! - L2 COS Value */
  COL_RES_NET_DST,    /**< 41) Resolved net dest */
  COL_UNRES_NET_DST,  /**< 42) Unresolved net dest */
  COL_RES_NET_SRC,    /**< 43) Resolved net source */
  COL_UNRES_NET_SRC,  /**< 44) Unresolved net source */
  COL_DEF_NET_DST,    /**< 45) Network layer dest address */
  COL_DEF_NET_SRC,    /**< 46) Network layer source address */
  COL_NUMBER,         /**< 47) Packet list item number */
  COL_PACKET_LENGTH,  /**< 48) Packet length in bytes */
  COL_PROTOCOL,       /**< 49) Protocol */
  COL_REL_TIME,       /**< 50) Relative time */
  COL_REL_CONV_TIME,  /**< 51) !! DEPRECATED !! - Relative time to beginning of conversation */
  COL_DEF_SRC,        /**< 52) Source address */
  COL_DEF_SRC_PORT,   /**< 53) Source port */
  COL_RES_SRC,        /**< 54) Resolved source */
  COL_UNRES_SRC,      /**< 55) Unresolved source */
  COL_RES_SRC_PORT,   /**< 56) Resolved source port */
  COL_UNRES_SRC_PORT, /**< 57) Unresolved source port */
  COL_TEI,            /**< 58) Q.921 TEI */
  COL_UTC_YMD_TIME,   /**< 59) UTC date, as YYYY-MM-DD, and time */
  COL_UTC_YDOY_TIME,  /**< 60) UTC date, as YYYY/DOY, and time */
  COL_UTC_TIME,       /**< 61) UTC time */
  COL_CLS_TIME,       /**< 62) Command line-specified time (default relative) */
  NUM_COL_FMTS        /**< 63) Should always be last */
};

/** Allocate all the data structures for constructing column data, given
 * the number of columns.
 *
 * Internal, don't use this in dissectors!
 */
WS_DLL_PUBLIC void	col_setup(column_info *cinfo, const gint num_cols);

/** Cleanup all the data structures for constructing column data;
 * undoes the alocations that col_setup() does.
 *
 * Internal, don't use this in dissectors!
 */
WS_DLL_PUBLIC void	col_cleanup(column_info *cinfo);

/** Initialize the data structures for constructing column data.
 *
 * Internal, don't use this in dissectors!
 */
extern void	col_init(column_info *cinfo, const struct epan_session *epan);

/** Fill in all columns of the given packet which are based on values from frame_data.
 *
 * Internal, don't use this in dissectors!
 */
WS_DLL_PUBLIC void col_fill_in_frame_data(const frame_data *fd, column_info *cinfo, const gint col, gboolean const fill_col_exprs);

/** Fill in all columns of the given packet.
 *
 * Internal, don't use this in dissectors!
 */
WS_DLL_PUBLIC void	col_fill_in(packet_info *pinfo, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Fill in columns if we got an error reading the packet.
 * We set most columns to "???", and set the Info column to an error
 * message.
 *
 * Internal, don't use this in dissectors!
 */
WS_DLL_PUBLIC void	col_fill_in_error(column_info *cinfo, frame_data *fdata, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/* Utility routines used by packet*.c */

/** Are the columns writable?
 *
 * @param cinfo the current packet row
 * @return TRUE if it's writable, FALSE if not
 */
WS_DLL_PUBLIC gboolean	col_get_writable(column_info *cinfo);

/** Set the columns writable.
 *
 * @param cinfo the current packet row
 * @param writable TRUE if it's writable, FALSE if not
 */
WS_DLL_PUBLIC void	col_set_writable(column_info *cinfo, const gboolean writable);

/** Sets a fence for the current column content,
 * so this content won't be affected by further col_... function calls.
 *
 * This can be useful if a protocol is more than once in a single packet,
 * e.g. multiple HTTP calls in a single TCP packet.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void	col_set_fence(column_info *cinfo, const gint col);

/** Clears a fence for the current column content
 *
 * This can be useful if a protocol wants to remove whatever
 * a previous protocol has added to the column.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void	col_clear_fence(column_info *cinfo, const gint col);

/** Gets the text of a column element.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 *
 * @return the text string
 */
extern const gchar *col_get_text(column_info *cinfo, const gint col);

/** Clears the text of a column element.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 */
WS_DLL_PUBLIC void	col_clear(column_info *cinfo, const gint col);

/** Set (replace) the text of a column element, the text won't be copied.
 *
 * Usually used to set const strings!
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to set
 */
WS_DLL_PUBLIC void	col_set_str(column_info *cinfo, const gint col, const gchar * str);

/** Add (replace) the text of a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to add
 */
WS_DLL_PUBLIC void	col_add_str(column_info *cinfo, const gint col, const gchar *str);

/* terminator argument for col_add_lstr() function */
#define COL_ADD_LSTR_TERMINATOR (const char *) -1
WS_DLL_PUBLIC void	col_add_lstr(column_info *cinfo, const gint el, const gchar *str, ...);

/** Add (replace) the text of a column element, the text will be formatted and copied.
 *
 * Same function as col_add_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void	col_add_fstr(column_info *cinfo, const gint col, const gchar *format, ...)
    G_GNUC_PRINTF(3, 4);

/** For internal Wireshark use only.  Not to be called from dissectors. */
void col_custom_set_edt(struct epan_dissect *edt, column_info *cinfo);

/** For internal Wireshark use only.  Not to be called from dissectors. */
WS_DLL_PUBLIC
void col_custom_prime_edt(struct epan_dissect *edt, column_info *cinfo);

/** For internal Wireshark use only.  Not to be called from dissectors. */
WS_DLL_PUBLIC
gboolean have_custom_cols(column_info *cinfo);
/** For internal Wireshark use only.  Not to be called from dissectors. */
WS_DLL_PUBLIC
gboolean col_has_time_fmt(column_info *cinfo, const gint col);
/** For internal Wireshark use only.  Not to be called from dissectors. */
WS_DLL_PUBLIC
gboolean col_based_on_frame_data(column_info *cinfo, const gint col);

/** Append the given text to a column element, the text will be copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param str the string to append
 */
WS_DLL_PUBLIC void	col_append_str(column_info *cinfo, const gint col, const gchar *str);

/* Append the given strings (terminated by COL_ADD_LSTR_TERMINATOR) to a column element,
 *
 * Same result as col_append_str() called for every string element.
 */
WS_DLL_PUBLIC void	col_append_lstr(column_info *cinfo, const gint el, const gchar *str, ...);

/** Append the given text to a column element, the text will be formatted and copied.
 *
 * Same function as col_append_str() but using a printf-like format string.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void	col_append_fstr(column_info *cinfo, const gint col, const gchar *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Prepend the given text to a column element, the text will be formatted and copied.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param format the format string
 * @param ... the variable number of parameters
 */
WS_DLL_PUBLIC void	col_prepend_fstr(column_info *cinfo, const gint col, const gchar *format, ...)
    G_GNUC_PRINTF(3, 4);

/**Prepend the given text to a column element, the text will be formatted and copied.
 * This function is similar to col_prepend_fstr() but this function will
 * unconditionally set a fence to the end of the prepended data even if there
 * were no fence before.
 * The col_prepend_fstr() will only prepend the data before the fence IF
 * there is already a fence created. This function will create a fence in case
 * it does not yet exist.
 */
WS_DLL_PUBLIC void	col_prepend_fence_fstr(column_info *cinfo, const gint col, const gchar *format, ...)
    G_GNUC_PRINTF(3, 4);

/** Append the given text (prepended by a separator) to a column element.
 *
 * Much like col_append_str() but will prepend the given separator if the column isn't empty.
 *
 * @param cinfo the current packet row
 * @param col the column to use, e.g. COL_INFO
 * @param sep the separator string or NULL for default: ", "
 * @param str the string to append
 */
WS_DLL_PUBLIC void	col_append_sep_str(column_info *cinfo, const gint col, const gchar *sep,
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
WS_DLL_PUBLIC void	col_append_sep_fstr(column_info *cinfo, const gint col, const gchar *sep,
		const gchar *format, ...)
    G_GNUC_PRINTF(4, 5);

/** Set the given (relative) time to a column element.
 *
 * Used by multiple dissectors to set the time in the column
 * COL_DELTA_CONV_TIME
 *
 * @param cinfo		the current packet row
 * @param col		the column to use, e.g. COL_INFO
 * @param ts		the time to set in the column
 * @param fieldname	the fieldname to use for creating a filter (when
 *			  applying/preparing/copying as filter)
 */
WS_DLL_PUBLIC void 	col_set_time(column_info *cinfo, const int col,
			const nstime_t *ts, const char *fieldname);

WS_DLL_PUBLIC void set_fd_time(const struct epan_session *epan, frame_data *fd, gchar *buf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_UTILS_H__ */

/* column-info.h
 * Definitions for column structures and routines
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __COLUMN_INFO_H__
#define __COLUMN_INFO_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Column info.
 */

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

/** Column expression */
typedef struct {
  const gchar **col_expr;     /**< Filter expression */
  gchar      **col_expr_val;  /**< Value for filter expression */
} col_expr_t;

/** Column info */
typedef struct _column_info {
  const struct epan_session *epan;
  gint                num_cols;             /**< Number of columns */
  gint               *col_fmt;              /**< Format of column */
  gboolean          **fmt_matx;             /**< Specifies which formats apply to a column */
  gint               *col_first;            /**< First column number with a given format */
  gint               *col_last;             /**< Last column number with a given format */
  gchar             **col_title;            /**< Column titles */
  gchar             **col_custom_field;     /**< Custom column field */
  gint               *col_custom_occurrence;/**< Custom column field occurrence */
  gint               *col_custom_field_id;  /**< Custom column field id */
  struct epan_dfilter **col_custom_dfilter; /**< Compiled custom column field */
  const gchar       **col_data;             /**< Column data */
  gchar             **col_buf;              /**< Buffer into which to copy data for column */
  int                *col_fence;            /**< Stuff in column buffer before this index is immutable */
  col_expr_t          col_expr;             /**< Column expressions and values */
  gboolean            writable;             /**< writable or not @todo Are we still writing to the columns? */
} column_info;

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_INFO_H__ */

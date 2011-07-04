/* column_info.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
  gint                num_cols;             /**< Number of columns */
  gint               *col_fmt;              /**< Format of column */
  gboolean          **fmt_matx;             /**< Specifies which formats apply to a column */
  gint               *col_first;            /**< First column number with a given format */
  gint               *col_last;             /**< Last column number with a given format */
  gchar             **col_title;            /**< Column titles */
  gchar             **col_custom_field;     /**< Custom column field */
  gint               *col_custom_occurrence;/**< Custom column field occurrence */
  gint               *col_custom_field_id;  /**< Custom column field id */
  struct _dfilter_t **col_custom_dfilter;   /**< Compiled custom column field */
  const gchar       **col_data;             /**< Column data */
  gchar             **col_buf;              /**< Buffer into which to copy data for column */
  int                *col_fence;            /**< Stuff in column buffer before this index is immutable */
  col_expr_t          col_expr;             /**< Column expressions and values */
  gboolean            writable;             /**< writable or not @todo Are we still writing to the columns? */
  gboolean            columns_changed;      /**< Have the columns been changed in the prefs? */
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
  COL_ABS_DATE_TIME,  /**< 1) Absolute date and time */
  COL_ABS_TIME,       /**< 2) Absolute time */
  COL_CIRCUIT_ID,     /**< 3) Circuit ID */
  COL_DSTIDX,         /**< 4) !! DEPRECATED !! - Dst port idx - Cisco MDS-specific */
  COL_SRCIDX,         /**< 5) !! DEPRECATED !! - Src port idx - Cisco MDS-specific */
  COL_VSAN,           /**< 6) VSAN - Cisco MDS-specific */
  COL_CUMULATIVE_BYTES, /**< 7) Cumulative number of bytes */
  COL_CUSTOM,         /**< 8) Custom column (any filter name's contents) */
  COL_DCE_CALL,       /**< 9) DCE/RPC connection oriented call id OR datagram sequence number */
  COL_DCE_CTX,        /**< 10) !! DEPRECATED !! - DCE/RPC connection oriented context id */
  COL_DELTA_TIME,     /**< 11) Delta time */
  COL_DELTA_CONV_TIME,/**< 12) Delta time to last frame in conversation */
  COL_DELTA_TIME_DIS, /**< 13) Delta time displayed*/
  COL_RES_DST,        /**< 14) Resolved dest */
  COL_UNRES_DST,      /**< 15) Unresolved dest */
  COL_RES_DST_PORT,   /**< 16) Resolved dest port */
  COL_UNRES_DST_PORT, /**< 17) Unresolved dest port */
  COL_DEF_DST,        /**< 18) Destination address */
  COL_DEF_DST_PORT,   /**< 19) Destination port */
  COL_EXPERT,         /**< 20) Expert Info */
  COL_IF_DIR,         /**< 21) FW-1 monitor interface/direction */
  COL_OXID,           /**< 22) !! DEPRECATED !! - Fibre Channel OXID */
  COL_RXID,           /**< 23) !! DEPRECATED !! - Fibre Channel RXID */
  COL_FR_DLCI,        /**< 24) !! DEPRECATED !! - Frame Relay DLCI */
  COL_FREQ_CHAN,      /**< 25) IEEE 802.11 (and WiMax?) - Channel */
  COL_BSSGP_TLLI,     /**< 26) !! DEPRECATED !! - GPRS BSSGP IE TLLI */
  COL_HPUX_DEVID,     /**< 27) !! DEPRECATED !! - HP-UX Nettl Device ID */
  COL_HPUX_SUBSYS,    /**< 28) !! DEPRECATED !! - HP-UX Nettl Subsystem */
  COL_DEF_DL_DST,     /**< 29) Data link layer dest address */
  COL_DEF_DL_SRC,     /**< 30) Data link layer source address */
  COL_RES_DL_DST,     /**< 31) Resolved DL dest */
  COL_UNRES_DL_DST,   /**< 32) Unresolved DL dest */
  COL_RES_DL_SRC,     /**< 33) Resolved DL source */
  COL_UNRES_DL_SRC,   /**< 34) Unresolved DL source */
  COL_RSSI,           /**< 35) IEEE 802.11 - received signal strength */
  COL_TX_RATE,        /**< 36) IEEE 802.11 - TX rate in Mbps */
  COL_DSCP_VALUE,     /**< 37) IP DSCP Value */
  COL_INFO,           /**< 38) Description */
  COL_COS_VALUE,      /**< 39) !! DEPRECATED !! - L2 COS Value */
  COL_RES_NET_DST,    /**< 40) Resolved net dest */
  COL_UNRES_NET_DST,  /**< 41) Unresolved net dest */
  COL_RES_NET_SRC,    /**< 42) Resolved net source */
  COL_UNRES_NET_SRC,  /**< 43) Unresolved net source */
  COL_DEF_NET_DST,    /**< 44) Network layer dest address */
  COL_DEF_NET_SRC,    /**< 45) Network layer source address */
  COL_NUMBER,         /**< 46) Packet list item number */
  COL_PACKET_LENGTH,  /**< 47) Packet length in bytes */
  COL_PROTOCOL,       /**< 48) Protocol */
  COL_REL_TIME,       /**< 49) Relative time */
  COL_REL_CONV_TIME,  /**< 50) !! DEPRECATED !! - Relative time to beginning of conversation */
  COL_DEF_SRC,        /**< 51) Source address */
  COL_DEF_SRC_PORT,   /**< 52) Source port */
  COL_RES_SRC,        /**< 53) Resolved source */
  COL_UNRES_SRC,      /**< 54) Unresolved source */
  COL_RES_SRC_PORT,   /**< 55) Resolved source port */
  COL_UNRES_SRC_PORT, /**< 56) Unresolved source port */
  COL_TEI,            /**< 57) Q.921 TEI */
  COL_UTC_DATE_TIME,  /**< 58) UTC date and time */
  COL_UTC_TIME,       /**< 59) UTC time */
  COL_CLS_TIME,       /**< 60) Command line-specified time (default relative) */
  NUM_COL_FMTS        /**< 61) Should always be last */
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COLUMN_INFO_H__ */

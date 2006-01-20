/* column.h
 * Definitions for column structures and routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

typedef struct _column_info {
  gint          num_cols;    /* Number of columns */
  gint         *col_fmt;     /* Format of column */
  gboolean    **fmt_matx;    /* Specifies which formats apply to a column */
  gint         *col_first;   /* First column number with a given format */
  gint         *col_last;    /* Last column number with a given format */
  gchar       **col_title;   /* Column titles */
  const gchar **col_data;    /* Column data */
  gchar       **col_buf;     /* Buffer into which to copy data for column */
  int         *col_fence;    /* Stuff in column buffer before this index is immutable */
  gchar      **col_expr;     /* Filter expression */
  gchar      **col_expr_val; /* Value for filter expression */
  gboolean     writable;     /* Are we still writing to the columns? */
} column_info;

/*
 * All of the possible columns in summary listing.
 *
 * NOTE: The SRC and DST entries MUST remain in this order, or else you
 * need to fix the offset #defines before get_column_format!
 */
enum {
  COL_NUMBER,         /* Packet list item number */
  COL_CLS_TIME,       /* Command line-specified time (default relative) */
  COL_REL_TIME,       /* Relative time */
  COL_ABS_TIME,       /* Absolute time */
  COL_ABS_DATE_TIME,  /* Absolute date and time */
  COL_DELTA_TIME,     /* Delta time */
  COL_DEF_SRC,        /* Source address */
  COL_RES_SRC,        /* Resolved source */
  COL_UNRES_SRC,      /* Unresolved source */
  COL_DEF_DL_SRC,     /* Data link layer source address */
  COL_RES_DL_SRC,     /* Resolved DL source */
  COL_UNRES_DL_SRC,   /* Unresolved DL source */
  COL_DEF_NET_SRC,    /* Network layer source address */
  COL_RES_NET_SRC,    /* Resolved net source */
  COL_UNRES_NET_SRC,  /* Unresolved net source */
  COL_DEF_DST,        /* Destination address */
  COL_RES_DST,        /* Resolved dest */
  COL_UNRES_DST,      /* Unresolved dest */
  COL_DEF_DL_DST,     /* Data link layer dest address */
  COL_RES_DL_DST,     /* Resolved DL dest */
  COL_UNRES_DL_DST,   /* Unresolved DL dest */
  COL_DEF_NET_DST,    /* Network layer dest address */
  COL_RES_NET_DST,    /* Resolved net dest */
  COL_UNRES_NET_DST,  /* Unresolved net dest */
  COL_DEF_SRC_PORT,   /* Source port */
  COL_RES_SRC_PORT,   /* Resolved source port */
  COL_UNRES_SRC_PORT, /* Unresolved source port */
  COL_DEF_DST_PORT,   /* Destination port */
  COL_RES_DST_PORT,   /* Resolved dest port */
  COL_UNRES_DST_PORT, /* Unresolved dest port */
  COL_PROTOCOL,       /* Protocol */
  COL_INFO,           /* Description */
  COL_PACKET_LENGTH,  /* Packet length in bytes */
  COL_CUMULATIVE_BYTES, /* Cumulative number of bytes */
  COL_OXID,           /* Fibre Channel OXID */
  COL_RXID,           /* Fibre Channel RXID */
  COL_IF_DIR,         /* FW-1 monitor interface/direction */
  COL_CIRCUIT_ID,     /* Circuit ID */
  COL_SRCIDX,         /* Src port idx - Cisco MDS-specific */
  COL_DSTIDX,         /* Dst port idx - Cisco MDS-specific */
  COL_VSAN,           /* VSAN - Cisco MDS-specific */
  COL_TX_RATE,        /* IEEE 802.11 - TX rate in Mbps */
  COL_RSSI,           /* IEEE 802.11 - received signal strength */
  COL_HPUX_SUBSYS,    /* HP-UX Nettl Subsystem */
  COL_HPUX_DEVID,     /* HP-UX Nettl Device ID */
  COL_DCE_CALL,       /* DCE/RPC call id OR datagram sequence number */
  COL_8021Q_VLAN_ID,  /* 802.1Q vlan ID */
  NUM_COL_FMTS        /* Should always be last */
};

#endif /* __COLUMN_INFO_H__ */




/* column.c
 * Routines for handling column preferences
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/nstime.h>
#include <epan/dfilter/dfilter.h>
#include <epan/column.h>
#include <epan/packet.h>

/* Given a format number (as defined in column_info.h), returns its equivalent
   string */
const gchar *
col_format_to_string(const gint fmt) {
  const gchar *slist[] = {
    "%q",                                       /* 0) COL_8021Q_VLAN_ID */
    "%Yt",                                      /* 1) COL_ABS_DATE_TIME */
    "%At",                                      /* 2) COL_ABS_TIME */
    "%c",                                       /* 3) COL_CIRCUIT_ID */
    "%Xd",                                      /* 4) COL_DSTIDX */
    "%Xs",                                      /* 5) COL_SRCIDX */
    "%V",                                       /* 6) COL_VSAN */
    "%B",                                       /* 7) COL_CUMULATIVE_BYTES */
    "%Cus",                                     /* 8) COL_CUSTOM */
    "%y",                                       /* 9) COL_DCE_CALL */
    "%z",                                       /* 10) COL_DCE_CTX */
    "%Tt",                                      /* 11) COL_DELTA_TIME */
    "%dct",                                     /* 12) COL_DELTA_CONV_TIME */
    "%Gt",                                      /* 13) COL_DELTA_TIME_DIS */
    "%rd",                                      /* 14) COL_RES_DST */
    "%ud",                                      /* 15) COL_UNRES_DST */
    "%rD",                                      /* 16) COL_RES_DST_PORT */
    "%uD",                                      /* 17) COL_UNRES_DST_PORT */
    "%d",                                       /* 18) COL_DEF_DST */
    "%D",                                       /* 19) COL_DEF_DST_PORT */
    "%a",                                       /* 20) COL_EXPERT */
    "%I",                                       /* 21) COL_IF_DIR */
    "%XO",                                      /* 22) COL_OXID */
    "%XR",                                      /* 23) COL_RXID */
    "%C",                                       /* 24) !! DEPRECATED !! - COL_FR_DLCI */
    "%F",                                       /* 25) COL_FREQ_CHAN */
    "%l",                                       /* 26) !! DEPRECATED !! - COL_BSSGP_TLLI */
    "%P",                                       /* 27) !! DEPRECATED !! - COL_HPUX_DEVID */
    "%H",                                       /* 28) !! DEPRECATED !! - COL_HPUX_SUBSYS */
    "%hd",                                      /* 29) COL_DEF_DL_DST */
    "%hs",                                      /* 30) COL_DEF_DL_SRC */
    "%rhd",                                     /* 31) COL_RES_DL_DST */
    "%uhd",                                     /* 32) COL_UNRES_DL_DST */
    "%rhs",                                     /* 33) COL_RES_DL_SRC*/
    "%uhs",                                     /* 34) COL_UNRES_DL_SRC */
    "%e",                                       /* 35) COL_RSSI */
    "%x",                                       /* 36) COL_TX_RATE */
    "%f",                                       /* 37) COL_DSCP_VALUE */
    "%i",                                       /* 38) COL_INFO */
    "%U",                                       /* 39) !! DEPRECATED !! - COL_COS_VALUE */
    "%rnd",                                     /* 40) COL_RES_NET_DST */
    "%und",                                     /* 41) COL_UNRES_NET_DST */
    "%rns",                                     /* 42) COL_RES_NET_SRC */
    "%uns",                                     /* 43) COL_UNRES_NET_SRC */
    "%nd",                                      /* 44) COL_DEF_NET_DST */
    "%ns",                                      /* 45) COL_DEF_NET_SRC */
    "%m",                                       /* 46) COL_NUMBER */
    "%L",                                       /* 47) COL_PACKET_LENGTH */
    "%p",                                       /* 48) COL_PROTOCOL */
    "%Rt",                                      /* 49) COL_REL_TIME */
    "%rct",                                     /* 50) !! DEPRECATED !! - COL_REL_CONV_TIME */
    "%s",                                       /* 51) COL_DEF_SRC */
    "%S",                                       /* 52) COL_DEF_SRC_PORT */
    "%rs",                                      /* 53) COL_RES_SRC */
    "%us",                                      /* 54) COL_UNRES_SRC */
    "%rS",                                      /* 55) COL_RES_SRC_PORT */
    "%uS",                                      /* 56) COL_UNRES_SRC_PORT */
    "%E",                                       /* 57) COL_TEI */
    "%Yut",                                     /* 58) COL_UTC_DATE_TIME */
    "%Aut",                                     /* 59) COL_UTC_TIME */
    "%t"                                        /* 60) COL_CLS_TIME */
  };

  if (fmt < 0 || fmt >= NUM_COL_FMTS)
    return NULL;

  return(slist[fmt]);
}

/* Given a format number (as defined in column_info.h), returns its
  description */
static const gchar *dlist[NUM_COL_FMTS] = {
    "802.1Q VLAN id",                           /* 0) COL_8021Q_VLAN_ID */
    "Absolute date and time",                   /* 1) COL_ABS_DATE_TIME */
    "Absolute time",                            /* 2) COL_ABS_TIME */
    "Circuit ID",                               /* 3) COL_CIRCUIT_ID */
    "Cisco Dst PortIdx",                        /* 4) COL_DSTIDX */
    "Cisco Src PortIdx",                        /* 5) COL_SRCIDX */
    "Cisco VSAN",                               /* 6) COL_VSAN */
    "Cumulative Bytes" ,                        /* 7) COL_CUMULATIVE_BYTES */
    "Custom",                                   /* 8) COL_CUSTOM */
    "DCE/RPC call (cn_call_id / dg_seqnum)",    /* 9) COL_DCE_CALL */
    "DCE/RPC context ID (cn_ctx_id)",           /* 10) COL_DCE_CTX */
    "Delta time",                               /* 11) COL_DELTA_TIME */
    "Delta time (conversation)",                /* 12) COL_DELTA_CONV_TIME */
    "Delta time displayed",                     /* 13) COL_DELTA_TIME_DIS */
    "Dest addr (resolved)",                     /* 14) COL_RES_DST */
    "Dest addr (unresolved)",                   /* 15) COL_UNRES_DST */
    "Dest port (resolved)",                     /* 16) COL_RES_DST_PORT */
    "Dest port (unresolved)",                   /* 17) COL_UNRES_DST_PORT */
    "Destination address",                      /* 18) COL_DEF_DST */
    "Destination port",                         /* 19) COL_DEF_DST_PORT */
    "Expert Info Severity",                     /* 20) COL_EXPERT */
    "FW-1 monitor if/direction",                /* 21) COL_IF_DIR */
    "Fibre Channel OXID",                       /* 22) COL_OXID */
    "Fibre Channel RXID",                       /* 23) COL_RXID */
    "Frame Relay DLCI",                         /* 24) !! DEPRECATED !! - COL_FR_DLCI */
    "Frequency/Channel",                        /* 25) COL_FREQ_CHAN */
    "GPRS BSSGP TLLI",                          /* 26) !! DEPRECATED !! - COL_BSSGP_TLLI */
    "HP-UX Device ID",                          /* 27) !! DEPRECATED !! - COL_HPUX_DEVID */
    "HP-UX Subsystem",                          /* 28) !! DEPRECATED !! - COL_HPUX_SUBSYS */
    "Hardware dest addr",                       /* 29) COL_DEF_DL_DST */
    "Hardware src addr",                        /* 30) COL_DEF_DL_SRC */
    "Hw dest addr (resolved)",                  /* 31) COL_RES_DL_DST */
    "Hw dest addr (unresolved)",                /* 32) COL_UNRES_DL_DST */
    "Hw src addr (resolved)",                   /* 33) COL_RES_DL_SRC*/
    "Hw src addr (unresolved)",                 /* 34) COL_UNRES_DL_SRC */
    "IEEE 802.11 RSSI",                         /* 35) COL_RSSI */
    "IEEE 802.11 TX rate",                      /* 36) COL_TX_RATE */
    "IP DSCP Value",                            /* 37) COL_DSCP_VALUE */
    "Information",                              /* 38) COL_INFO */
    "L2 COS Value (802.1p)",                    /* 39) !! DEPRECATED !! - COL_COS_VALUE */
    "Net dest addr (resolved)",                 /* 40) COL_RES_NET_DST */
    "Net dest addr (unresolved)",               /* 41) COL_UNRES_NET_DST */
    "Net src addr (resolved)",                  /* 42) COL_RES_NET_SRC */
    "Net src addr (unresolved)",                /* 43) COL_UNRES_NET_SRC */
    "Network dest addr",                        /* 44) COL_DEF_NET_DST */
    "Network src addr",                         /* 45) COL_DEF_NET_SRC */
    "Number",                                   /* 46) COL_NUMBER */
    "Packet length (bytes)" ,                   /* 47) COL_PACKET_LENGTH */
    "Protocol",                                 /* 48) COL_PROTOCOL */
    "Relative time",                            /* 49) COL_REL_TIME */
    "Relative time (conversation)",             /* 50) !! DEPRECATED !! - COL_REL_CONV_TIME */
    "Source address",                           /* 51) COL_DEF_SRC */
    "Source port",                              /* 52) COL_DEF_SRC_PORT */
    "Src addr (resolved)",                      /* 53) COL_RES_SRC */
    "Src addr (unresolved)",                    /* 54) COL_UNRES_SRC */
    "Src port (resolved)",                      /* 55) COL_RES_SRC_PORT */
    "Src port (unresolved)",                    /* 56) COL_UNRES_SRC_PORT */
    "TEI",                                      /* 57) COL_TEI */
    "UTC date and time",                        /* 58) COL_UTC_DATE_TIME */
    "UTC time",                                 /* 59) COL_UTC_TIME */
    "Time (format as specified)"                /* 60) COL_CLS_TIME */
};

const gchar *
col_format_desc(const gint fmt) {
  g_assert((fmt >= 0) && (fmt < NUM_COL_FMTS));
  return(dlist[fmt]);
}

/* Marks each array element true if it can be substituted for the given
   column format */
void
get_column_format_matches(gboolean *fmt_list, const gint format) {

  /* Get the obvious: the format itself */
  if ((format >= 0) && (format < NUM_COL_FMTS))
    fmt_list[format] = TRUE;

  /* Get any formats lower down on the chain */
  switch (format) {
    case COL_DEF_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_RES_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_UNRES_SRC:
      fmt_list[COL_UNRES_DL_SRC] = TRUE;
      fmt_list[COL_UNRES_NET_SRC] = TRUE;
      break;
    case COL_DEF_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_RES_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_UNRES_DST:
      fmt_list[COL_UNRES_DL_DST] = TRUE;
      fmt_list[COL_UNRES_NET_DST] = TRUE;
      break;
    case COL_DEF_DL_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      break;
    case COL_DEF_DL_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      break;
    case COL_DEF_NET_SRC:
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_DEF_NET_DST:
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_DEF_SRC_PORT:
      fmt_list[COL_RES_SRC_PORT] = TRUE;
      break;
    case COL_DEF_DST_PORT:
      fmt_list[COL_RES_DST_PORT] = TRUE;
      break;
    case COL_OXID:
      fmt_list[COL_OXID] = TRUE;
      break;
    case COL_RXID:
      fmt_list[COL_RXID] = TRUE;
      break;
    case COL_IF_DIR:
      fmt_list[COL_IF_DIR] = TRUE;
      break;
    case COL_CIRCUIT_ID:
      fmt_list[COL_CIRCUIT_ID] = TRUE;
      break;
    case COL_SRCIDX:
      fmt_list[COL_SRCIDX] = TRUE;
      break;
    case COL_DSTIDX:
      fmt_list[COL_DSTIDX] = TRUE;
      break;
    case COL_VSAN:
      fmt_list[COL_VSAN] = TRUE;
      break;
    case COL_TX_RATE:
      fmt_list[COL_TX_RATE] = TRUE;
      break;
    case COL_RSSI:
      fmt_list[COL_RSSI] = TRUE;
      break;
    case COL_HPUX_SUBSYS:
      fmt_list[COL_HPUX_SUBSYS] = TRUE;
      break;
    case COL_HPUX_DEVID:
      fmt_list[COL_HPUX_DEVID] = TRUE;
      break;
    case COL_DCE_CALL:
      fmt_list[COL_DCE_CALL] = TRUE;
      break;
    case COL_DCE_CTX:
      fmt_list[COL_DCE_CTX] = TRUE;
      break;
    case COL_8021Q_VLAN_ID:
      fmt_list[COL_8021Q_VLAN_ID] = TRUE;
      break;
    case COL_DSCP_VALUE:
      fmt_list[COL_DSCP_VALUE] = TRUE;
      break;
    case COL_COS_VALUE:
      fmt_list[COL_COS_VALUE] = TRUE;
      break;
    case COL_TEI:
      fmt_list[COL_TEI] = TRUE;
      break;
    case COL_FR_DLCI:
      fmt_list[COL_FR_DLCI] = TRUE;
      break;
    case COL_BSSGP_TLLI:
      fmt_list[COL_BSSGP_TLLI] = TRUE;
      break;
    case COL_EXPERT:
      fmt_list[COL_EXPERT] = TRUE;
      break;
    case COL_FREQ_CHAN:
      fmt_list[COL_FREQ_CHAN] = TRUE;
      break;
    case COL_CUSTOM:
      fmt_list[COL_CUSTOM] = TRUE;
      break;
    default:
      break;
  }
}

/* Returns a string representing the longest possible value for
   a timestamp column type. */
static const char *
get_timestamp_column_longest_string(const gint type, const gint precision)
{

    switch(type) {
    case(TS_ABSOLUTE_WITH_DATE):
    case(TS_UTC_WITH_DATE):
        switch(precision) {
            case(TS_PREC_AUTO_SEC):
            case(TS_PREC_FIXED_SEC):
                return "0000-00-00 00:00:00";
                break;
            case(TS_PREC_AUTO_DSEC):
            case(TS_PREC_FIXED_DSEC):
                return "0000-00-00 00:00:00.0";
                break;
            case(TS_PREC_AUTO_CSEC):
            case(TS_PREC_FIXED_CSEC):
                return "0000-00-00 00:00:00.00";
                break;
            case(TS_PREC_AUTO_MSEC):
            case(TS_PREC_FIXED_MSEC):
                return "0000-00-00 00:00:00.000";
                break;
            case(TS_PREC_AUTO_USEC):
            case(TS_PREC_FIXED_USEC):
                return "0000-00-00 00:00:00.000000";
                break;
            case(TS_PREC_AUTO_NSEC):
            case(TS_PREC_FIXED_NSEC):
                return "0000-00-00 00:00:00.000000000";
                break;
            default:
                g_assert_not_reached();
        }
            break;
    case(TS_ABSOLUTE):
    case(TS_UTC):
        switch(precision) {
            case(TS_PREC_AUTO_SEC):
            case(TS_PREC_FIXED_SEC):
                return "00:00:00";
                break;
            case(TS_PREC_AUTO_DSEC):
            case(TS_PREC_FIXED_DSEC):
                return "00:00:00.0";
                break;
            case(TS_PREC_AUTO_CSEC):
            case(TS_PREC_FIXED_CSEC):
                return "00:00:00.00";
                break;
            case(TS_PREC_AUTO_MSEC):
            case(TS_PREC_FIXED_MSEC):
                return "00:00:00.000";
                break;
            case(TS_PREC_AUTO_USEC):
            case(TS_PREC_FIXED_USEC):
                return "00:00:00.000000";
                break;
            case(TS_PREC_AUTO_NSEC):
            case(TS_PREC_FIXED_NSEC):
                return "00:00:00.000000000";
                break;
            default:
                g_assert_not_reached();
        }
        break;
    case(TS_RELATIVE):  /* fallthrough */
    case(TS_DELTA):
    case(TS_DELTA_DIS):
        switch(precision) {
            case(TS_PREC_AUTO_SEC):
            case(TS_PREC_FIXED_SEC):
                return "0000";
                break;
            case(TS_PREC_AUTO_DSEC):
            case(TS_PREC_FIXED_DSEC):
                return "0000.0";
                break;
            case(TS_PREC_AUTO_CSEC):
            case(TS_PREC_FIXED_CSEC):
                return "0000.00";
                break;
            case(TS_PREC_AUTO_MSEC):
            case(TS_PREC_FIXED_MSEC):
                return "0000.000";
                break;
            case(TS_PREC_AUTO_USEC):
            case(TS_PREC_FIXED_USEC):
                return "0000.000000";
                break;
            case(TS_PREC_AUTO_NSEC):
            case(TS_PREC_FIXED_NSEC):
                return "0000.000000000";
                break;
            default:
                g_assert_not_reached();
        }
        break;
    case(TS_EPOCH):
        /* This is enough to represent 2^63 (signed 64-bit integer) + fractions */
        switch(precision) {
            case(TS_PREC_AUTO_SEC):
            case(TS_PREC_FIXED_SEC):
                return "0000000000000000000";
                break;
            case(TS_PREC_AUTO_DSEC):
            case(TS_PREC_FIXED_DSEC):
                return "0000000000000000000.0";
                break;
            case(TS_PREC_AUTO_CSEC):
            case(TS_PREC_FIXED_CSEC):
                return "0000000000000000000.00";
                break;
            case(TS_PREC_AUTO_MSEC):
            case(TS_PREC_FIXED_MSEC):
                return "0000000000000000000.000";
                break;
            case(TS_PREC_AUTO_USEC):
            case(TS_PREC_FIXED_USEC):
                return "0000000000000000000.000000";
                break;
            case(TS_PREC_AUTO_NSEC):
            case(TS_PREC_FIXED_NSEC):
                return "0000000000000000000.000000000";
                break;
            default:
                g_assert_not_reached();
        }
        break;
    case(TS_NOT_SET):
        return "0000.000000";
        break;
    default:
        g_assert_not_reached();
    }

    /* never reached, satisfy compiler */
    return "";
}

/* Returns the longer string of the column title or the hard-coded width of
 * its contents for building the packet list layout. */
const gchar *
get_column_width_string(const gint format, const gint col)
{
    if(strlen(get_column_longest_string(format)) >
       strlen(get_column_title(col)))
        return get_column_longest_string(format);
    else
        return get_column_title(col);
}

/* Returns a string representing the longest possible value for a
   particular column type.  See also get_column_width_string() above.

   Except for the COL...SRC and COL...DST columns, these are used
   only when a capture is being displayed while it's taking place;
   they are arguably somewhat fragile, as changes to the code that
   generates them don't cause these widths to change, but that's
   probably not too big a problem, given that the sizes are
   recomputed based on the actual data in the columns when the capture
   is done, and given that the width for COL...SRC and COL...DST columns
   is somewhat arbitrary in any case.  We should probably clean
   that up eventually, though. */
const char *
get_column_longest_string(const gint format)
{
  switch (format) {
    case COL_NUMBER:
      return "0000000";
      break;
    case COL_CLS_TIME:
      return get_timestamp_column_longest_string(timestamp_get_type(), timestamp_get_precision());
      break;
    case COL_ABS_DATE_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_DATE, timestamp_get_precision());
      break;
    case COL_UTC_DATE_TIME:
      return get_timestamp_column_longest_string(TS_UTC_WITH_DATE, timestamp_get_precision());
      break;
    case COL_ABS_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE, timestamp_get_precision());
      break;
    case COL_UTC_TIME:
      return get_timestamp_column_longest_string(TS_UTC, timestamp_get_precision());
      break;
    case COL_REL_TIME:
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
      break;
    case COL_DELTA_TIME:
      return get_timestamp_column_longest_string(TS_DELTA, timestamp_get_precision());
      break;
    case COL_DELTA_TIME_DIS:
      return get_timestamp_column_longest_string(TS_DELTA_DIS, timestamp_get_precision());
      break;
    case COL_REL_CONV_TIME: /* 'abuse' TS_RELATIVE to set the time format */
    case COL_DELTA_CONV_TIME:   /* for the conversation related time columns */
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
      break;
    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      return "00000000.000000000000"; /* IPX-style */
      break;
    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
      return "000000";
      break;
    case COL_PROTOCOL:
      return "Protocol";    /* not the longest, but the longest is too long */
      break;
    case COL_PACKET_LENGTH:
      return "00000";
      break;
    case COL_CUMULATIVE_BYTES:
      return "00000000";
      break;
    case COL_RXID:
    case COL_OXID:
      return "000000";
      break;
    case COL_IF_DIR:
      return "i 00000000 I";
      break;
    case COL_CIRCUIT_ID:
      return "000000";
      break;
    case COL_SRCIDX:
    case COL_DSTIDX:
      return "0000000";
      break;
    case COL_VSAN:
     return "000000";
      break;
    case COL_TX_RATE:
      return "108.0";
      break;
    case COL_RSSI:
      return "100";
      break;
    case COL_HPUX_SUBSYS:
      return "OTS9000-TRANSPORT";
      break;
    case COL_HPUX_DEVID:
      return "0000";
      break;
    case COL_DCE_CALL:
      return "0000";
      break;
    case COL_DCE_CTX:
      return "0000";
      break;
    case COL_8021Q_VLAN_ID:
      return "0000";
      break;
    case COL_DSCP_VALUE:
      return "00";
      break;
    case COL_COS_VALUE:
      return "0";
      break;
    case COL_TEI:
      return "127";
      break;
    case COL_FR_DLCI:
      return "8388608";
      break;
    case COL_BSSGP_TLLI:
      return "0xffffffff";
      break;
    case COL_EXPERT:
      return "ERROR";
      break;
    case COL_FREQ_CHAN:
      return "9999 MHz [A 999]";
      break;
    case COL_CUSTOM:
      return "0000000000";  /* not the longest, but the longest is too long */
      break;
    default: /* COL_INFO */
      return "Source port: kerberos-master  Destination port: kerberos-master";
      break;
  }
}

/* Returns the longest possible width, in characters, for a particular
   column type. */
gint
get_column_char_width(const gint format)
{
  return (gint)strlen(get_column_longest_string(format));
}

gint
get_column_format(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return -1;

  cfmt = (fmt_data *) clp->data;

  return(get_column_format_from_str(cfmt->fmt));
}

void
set_column_format(const gint col, const gint fmt)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->fmt);
  cfmt->fmt = g_strdup(col_format_to_string(fmt));
}

gint
get_column_format_from_str(const gchar *str)
{
  gint i;

  for (i = 0; i < NUM_COL_FMTS; i++) {
    if (strcmp(str, col_format_to_string(i)) == 0)
      return i;
  }
  return -1;    /* illegal */
}

gchar *
get_column_title(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return NULL;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);
}

void
set_column_title(const gint col, const gchar *title)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->title);
  cfmt->title = g_strdup (title);
}

gboolean
get_column_visible(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return TRUE;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->visible);
}

void
set_column_visible(const gint col, gboolean visible)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->visible = visible;
}

gboolean
get_column_resolved(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return TRUE;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->resolved);
}

void
set_column_resolved(const gint col, gboolean resolved)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->resolved = resolved;
}

const gchar *
get_column_custom_field(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return NULL;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_field);
}

void
set_column_custom_field(const gint col, const char *custom_field)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->custom_field);
  cfmt->custom_field = g_strdup (custom_field);
}

gint
get_column_custom_occurrence(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return 0;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_occurrence);
}

void
set_column_custom_occurrence(const gint col, const gint custom_occurrence)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->custom_occurrence = custom_occurrence;
}

void
build_column_format_array(column_info *cinfo, const gint num_cols, const gboolean reset_fences)
{
  int i;

  /* Build the column format array */
  col_setup(cinfo, num_cols);

  for (i = 0; i < cinfo->num_cols; i++) {
    cinfo->col_fmt[i] = get_column_format(i);
    cinfo->col_title[i] = g_strdup(get_column_title(i));

    if (cinfo->col_fmt[i] == COL_CUSTOM) {
      cinfo->col_custom_field[i] = g_strdup(get_column_custom_field(i));
      cinfo->col_custom_occurrence[i] = get_column_custom_occurrence(i);
      if(!dfilter_compile(cinfo->col_custom_field[i], &cinfo->col_custom_dfilter[i])) {
        /* XXX: Should we issue a warning? */
        g_free(cinfo->col_custom_field[i]);
        cinfo->col_custom_field[i] = NULL;
        cinfo->col_custom_occurrence[i] = 0;
        cinfo->col_custom_dfilter[i] = NULL;
      }
    } else {
      cinfo->col_custom_field[i] = NULL;
      cinfo->col_custom_occurrence[i] = 0;
      cinfo->col_custom_dfilter[i] = NULL;
    }

    cinfo->fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) * NUM_COL_FMTS);
    get_column_format_matches(cinfo->fmt_matx[i], cinfo->col_fmt[i]);
    cinfo->col_data[i] = NULL;

    if (cinfo->col_fmt[i] == COL_INFO)
      cinfo->col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cinfo->col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);

    if(reset_fences)
      cinfo->col_fence[i] = 0;

    cinfo->col_expr.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cinfo->col_expr.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  cinfo->col_expr.col_expr[i] = NULL;
  cinfo->col_expr.col_expr_val[i] = NULL;

  for (i = 0; i < cinfo->num_cols; i++) {
    int j;

    for (j = 0; j < NUM_COL_FMTS; j++) {
      if (!cinfo->fmt_matx[i][j])
          continue;

      if (cinfo->col_first[j] == -1)
        cinfo->col_first[j] = i;

      cinfo->col_last[j] = i;
    }
  }
}


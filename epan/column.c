/* column.c
 * Routines for handling column preferences
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <epan/column.h>
#include <epan/packet.h>

/* Given a format number (as defined in column-utils.h), returns its equivalent
   string */
const gchar *
col_format_to_string(const gint fmt) {
  static const gchar *const slist[NUM_COL_FMTS] = {
    "%q",                                       /* 0) COL_8021Q_VLAN_ID */
    "%Yt",                                      /* 1) COL_ABS_YMD_TIME */
    "%YDOYt",                                   /* 2) COL_ABS_YDOY_TIME */
    "%At",                                      /* 3) COL_ABS_TIME */
    "%c",                                       /* 4) COL_CIRCUIT_ID */
    "%Xd",                                      /* 5) COL_DSTIDX - !! DEPRECATED !!*/
    "%Xs",                                      /* 6) COL_SRCIDX - !! DEPRECATED !!*/
    "%V",                                       /* 7) COL_VSAN - !! DEPRECATED !!*/
    "%B",                                       /* 8) COL_CUMULATIVE_BYTES */
    "%Cus",                                     /* 9) COL_CUSTOM */
    "%y",                                       /* 10) COL_DCE_CALL */
    "%z",                                       /* 11) COL_DCE_CTX */
    "%Tt",                                      /* 12) COL_DELTA_TIME */
    "%dct",                                     /* 13) COL_DELTA_CONV_TIME */
    "%Gt",                                      /* 14) COL_DELTA_TIME_DIS */
    "%rd",                                      /* 15) COL_RES_DST */
    "%ud",                                      /* 16) COL_UNRES_DST */
    "%rD",                                      /* 17) COL_RES_DST_PORT */
    "%uD",                                      /* 18) COL_UNRES_DST_PORT */
    "%d",                                       /* 19) COL_DEF_DST */
    "%D",                                       /* 20) COL_DEF_DST_PORT */
    "%a",                                       /* 21) COL_EXPERT */
    "%I",                                       /* 22) COL_IF_DIR */
    "%XO",                                      /* 23) COL_OXID */
    "%XR",                                      /* 24) COL_RXID */
    "%C",                                       /* 25) !! DEPRECATED !! - COL_FR_DLCI */
    "%F",                                       /* 26) COL_FREQ_CHAN */
    "%l",                                       /* 27) !! DEPRECATED !! - COL_BSSGP_TLLI */
    "%P",                                       /* 28) !! DEPRECATED !! - COL_HPUX_DEVID */
    "%H",                                       /* 29) !! DEPRECATED !! - COL_HPUX_SUBSYS */
    "%hd",                                      /* 30) COL_DEF_DL_DST */
    "%hs",                                      /* 31) COL_DEF_DL_SRC */
    "%rhd",                                     /* 32) COL_RES_DL_DST */
    "%uhd",                                     /* 33) COL_UNRES_DL_DST */
    "%rhs",                                     /* 34) COL_RES_DL_SRC*/
    "%uhs",                                     /* 35) COL_UNRES_DL_SRC */
    "%e",                                       /* 36) COL_RSSI */
    "%x",                                       /* 37) COL_TX_RATE */
    "%f",                                       /* 38) COL_DSCP_VALUE */
    "%i",                                       /* 39) COL_INFO */
    "%U",                                       /* 40) !! DEPRECATED !! - COL_COS_VALUE */
    "%rnd",                                     /* 41) COL_RES_NET_DST */
    "%und",                                     /* 42) COL_UNRES_NET_DST */
    "%rns",                                     /* 43) COL_RES_NET_SRC */
    "%uns",                                     /* 44) COL_UNRES_NET_SRC */
    "%nd",                                      /* 45) COL_DEF_NET_DST */
    "%ns",                                      /* 46) COL_DEF_NET_SRC */
    "%m",                                       /* 47) COL_NUMBER */
    "%L",                                       /* 48) COL_PACKET_LENGTH */
    "%p",                                       /* 49) COL_PROTOCOL */
    "%Rt",                                      /* 50) COL_REL_TIME */
    "%rct",                                     /* 51) !! DEPRECATED !! - COL_REL_CONV_TIME */
    "%s",                                       /* 52) COL_DEF_SRC */
    "%S",                                       /* 53) COL_DEF_SRC_PORT */
    "%rs",                                      /* 54) COL_RES_SRC */
    "%us",                                      /* 55) COL_UNRES_SRC */
    "%rS",                                      /* 56) COL_RES_SRC_PORT */
    "%uS",                                      /* 57) COL_UNRES_SRC_PORT */
    "%E",                                       /* 58) COL_TEI */
    "%Yut",                                     /* 59) COL_UTC_YMD_TIME */
    "%YDOYut",                                  /* 60) COL_UTC_YDOY_TIME */
    "%Aut",                                     /* 61) COL_UTC_TIME */
    "%t"                                        /* 62) COL_CLS_TIME */
  };

  if (fmt < 0 || fmt >= NUM_COL_FMTS)
    return NULL;

  return(slist[fmt]);
}

/* Given a format number (as defined in column-utils.h), returns its
  description */
const gchar *
col_format_desc(const gint fmt) {
  static const gchar *const dlist[NUM_COL_FMTS] = {
    "802.1Q VLAN id",                           /* 0) COL_8021Q_VLAN_ID */
    "Absolute date, as YYYY-MM-DD, and time",   /* 1) COL_ABS_YMD_TIME */
    "Absolute date, as YYYY/DOY, and time",     /* 2) COL_ABS_YDOY_TIME */
    "Absolute time",                            /* 3) COL_ABS_TIME */
    "Circuit ID",                               /* 4) COL_CIRCUIT_ID */
    "Cisco Dst PortIdx",                        /* 5) COL_DSTIDX */
    "Cisco Src PortIdx",                        /* 6) COL_SRCIDX */
    "Cisco VSAN",                               /* 7) COL_VSAN */
    "Cumulative Bytes" ,                        /* 8) COL_CUMULATIVE_BYTES */
    "Custom",                                   /* 9) COL_CUSTOM */
    "DCE/RPC call (cn_call_id / dg_seqnum)",    /* 10) COL_DCE_CALL */
    "DCE/RPC context ID (cn_ctx_id)",           /* 11) COL_DCE_CTX */
    "Delta time",                               /* 12) COL_DELTA_TIME */
    "Delta time (conversation)",                /* 13) COL_DELTA_CONV_TIME */
    "Delta time displayed",                     /* 14) COL_DELTA_TIME_DIS */
    "Dest addr (resolved)",                     /* 15) COL_RES_DST */
    "Dest addr (unresolved)",                   /* 16) COL_UNRES_DST */
    "Dest port (resolved)",                     /* 17) COL_RES_DST_PORT */
    "Dest port (unresolved)",                   /* 18) COL_UNRES_DST_PORT */
    "Destination address",                      /* 19) COL_DEF_DST */
    "Destination port",                         /* 20) COL_DEF_DST_PORT */
    "Expert Info Severity",                     /* 21) COL_EXPERT */
    "FW-1 monitor if/direction",                /* 22) COL_IF_DIR */
    "Fibre Channel OXID",                       /* 23) COL_OXID */
    "Fibre Channel RXID",                       /* 24) COL_RXID */
    "Frame Relay DLCI",                         /* 25) !! DEPRECATED !! - COL_FR_DLCI */
    "Frequency/Channel",                        /* 26) COL_FREQ_CHAN */
    "GPRS BSSGP TLLI",                          /* 27) !! DEPRECATED !! - COL_BSSGP_TLLI */
    "HP-UX Device ID",                          /* 28) !! DEPRECATED !! - COL_HPUX_DEVID */
    "HP-UX Subsystem",                          /* 29) !! DEPRECATED !! - COL_HPUX_SUBSYS */
    "Hardware dest addr",                       /* 30) COL_DEF_DL_DST */
    "Hardware src addr",                        /* 31) COL_DEF_DL_SRC */
    "Hw dest addr (resolved)",                  /* 32) COL_RES_DL_DST */
    "Hw dest addr (unresolved)",                /* 33) COL_UNRES_DL_DST */
    "Hw src addr (resolved)",                   /* 34) COL_RES_DL_SRC*/
    "Hw src addr (unresolved)",                 /* 35) COL_UNRES_DL_SRC */
    "IEEE 802.11 RSSI",                         /* 36) COL_RSSI */
    "IEEE 802.11 TX rate",                      /* 37) COL_TX_RATE */
    "IP DSCP Value",                            /* 38) COL_DSCP_VALUE */
    "Information",                              /* 39) COL_INFO */
    "L2 COS Value (802.1p)",                    /* 40) !! DEPRECATED !! - COL_COS_VALUE */
    "Net dest addr (resolved)",                 /* 41) COL_RES_NET_DST */
    "Net dest addr (unresolved)",               /* 42) COL_UNRES_NET_DST */
    "Net src addr (resolved)",                  /* 43) COL_RES_NET_SRC */
    "Net src addr (unresolved)",                /* 44) COL_UNRES_NET_SRC */
    "Network dest addr",                        /* 45) COL_DEF_NET_DST */
    "Network src addr",                         /* 46) COL_DEF_NET_SRC */
    "Number",                                   /* 47) COL_NUMBER */
    "Packet length (bytes)" ,                   /* 48) COL_PACKET_LENGTH */
    "Protocol",                                 /* 49) COL_PROTOCOL */
    "Relative time",                            /* 50) COL_REL_TIME */
    "Relative time (conversation)",             /* 51) !! DEPRECATED !! - COL_REL_CONV_TIME */
    "Source address",                           /* 52) COL_DEF_SRC */
    "Source port",                              /* 53) COL_DEF_SRC_PORT */
    "Src addr (resolved)",                      /* 54) COL_RES_SRC */
    "Src addr (unresolved)",                    /* 55) COL_UNRES_SRC */
    "Src port (resolved)",                      /* 56) COL_RES_SRC_PORT */
    "Src port (unresolved)",                    /* 57) COL_UNRES_SRC_PORT */
    "TEI",                                      /* 58) COL_TEI */
    "UTC date, as YYYY-MM-DD, and time",        /* 59) COL_UTC_YMD_TIME */
    "UTC date, as YYYY/DOY, and time",          /* 60) COL_UTC_YDOY_TIME */
    "UTC time",                                 /* 61) COL_UTC_TIME */
    "Time (format as specified)"                /* 62) COL_CLS_TIME */
  };

  g_assert((fmt >= 0) && (fmt < NUM_COL_FMTS));
  return(dlist[fmt]);
}

void
column_dump_column_formats(void)
{
  gint fmt;

  for (fmt = 0; fmt < NUM_COL_FMTS; fmt++) {
    printf("%s\t%s\n", col_format_to_string(fmt), col_format_desc(fmt));
  }

  printf("\nFor example, to print Wireshark's default columns with tshark:\n\n"
#ifdef _WIN32
  "tshark.exe -o \"gui.column.format:"
    "\\\"No.\\\",\\\"%%m\\\","
    "\\\"Time\\\",\\\"%%t\\\","
    "\\\"Source\\\",\\\"%%s\\\","
    "\\\"Destination\\\",\\\"%%d\\\","
    "\\\"Protocol\\\",\\\"%%p\\\","
    "\\\"Length\\\",\\\"%%L\\\","
    "\\\"Info\\\",\\\"%%i\\\"\"\n");
#else
  "tshark -o 'gui.column.format:"
    "\"No.\",\"%%m\","
    "\"Time\",\"%%t\","
    "\"Source\",\"%%s\","
    "\"Destination\",\"%%d\","
    "\"Protocol\",\"%%p\","
    "\"Length\",\"%%L\","
    "\"Info\",\"%%i\"'\n");
#endif
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
    case(TS_ABSOLUTE_WITH_YMD):
    case(TS_UTC_WITH_YMD):
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
    case(TS_ABSOLUTE_WITH_YDOY):
    case(TS_UTC_WITH_YDOY):
        switch(precision) {
            case(TS_PREC_AUTO_SEC):
            case(TS_PREC_FIXED_SEC):
                return "0000/000 00:00:00";
                break;
            case(TS_PREC_AUTO_DSEC):
            case(TS_PREC_FIXED_DSEC):
                return "0000/000 00:00:00.0";
                break;
            case(TS_PREC_AUTO_CSEC):
            case(TS_PREC_FIXED_CSEC):
                return "0000/000 00:00:00.00";
                break;
            case(TS_PREC_AUTO_MSEC):
            case(TS_PREC_FIXED_MSEC):
                return "0000/000 00:00:00.000";
                break;
            case(TS_PREC_AUTO_USEC):
            case(TS_PREC_FIXED_USEC):
                return "0000/000 00:00:00.000000";
                break;
            case(TS_PREC_AUTO_NSEC):
            case(TS_PREC_FIXED_NSEC):
                return "0000/000 00:00:00.000000000";
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
    case COL_ABS_YMD_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_YMD, timestamp_get_precision());
      break;
    case COL_ABS_YDOY_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_YDOY, timestamp_get_precision());
      break;
    case COL_UTC_YMD_TIME:
      return get_timestamp_column_longest_string(TS_UTC_WITH_YMD, timestamp_get_precision());
      break;
    case COL_UTC_YDOY_TIME:
      return get_timestamp_column_longest_string(TS_UTC_WITH_YDOY, timestamp_get_precision());
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
      return "00000000";
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

  return(cfmt->fmt);
}

void
set_column_format(const gint col, const gint fmt)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->fmt = fmt;
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */


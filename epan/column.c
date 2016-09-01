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
    "%V",                                       /* 4) COL_VSAN - !! DEPRECATED !!*/
    "%B",                                       /* 5) COL_CUMULATIVE_BYTES */
    "%Cus",                                     /* 6) COL_CUSTOM */
    "%y",                                       /* 7) COL_DCE_CALL */
    "%Tt",                                      /* 8) COL_DELTA_TIME */
    "%Gt",                                      /* 9) COL_DELTA_TIME_DIS */
    "%rd",                                      /* 10) COL_RES_DST */
    "%ud",                                      /* 11) COL_UNRES_DST */
    "%rD",                                      /* 12) COL_RES_DST_PORT */
    "%uD",                                      /* 13) COL_UNRES_DST_PORT */
    "%d",                                       /* 14) COL_DEF_DST */
    "%D",                                       /* 15) COL_DEF_DST_PORT */
    "%a",                                       /* 16) COL_EXPERT */
    "%I",                                       /* 17) COL_IF_DIR */
    "%F",                                       /* 18) COL_FREQ_CHAN */
    "%hd",                                      /* 19) COL_DEF_DL_DST */
    "%hs",                                      /* 20) COL_DEF_DL_SRC */
    "%rhd",                                     /* 21) COL_RES_DL_DST */
    "%uhd",                                     /* 22) COL_UNRES_DL_DST */
    "%rhs",                                     /* 23) COL_RES_DL_SRC*/
    "%uhs",                                     /* 24) COL_UNRES_DL_SRC */
    "%e",                                       /* 25) COL_RSSI */
    "%x",                                       /* 26) COL_TX_RATE */
    "%f",                                       /* 27) COL_DSCP_VALUE */
    "%i",                                       /* 28) COL_INFO */
    "%rnd",                                     /* 29) COL_RES_NET_DST */
    "%und",                                     /* 30) COL_UNRES_NET_DST */
    "%rns",                                     /* 31) COL_RES_NET_SRC */
    "%uns",                                     /* 32) COL_UNRES_NET_SRC */
    "%nd",                                      /* 33) COL_DEF_NET_DST */
    "%ns",                                      /* 34) COL_DEF_NET_SRC */
    "%m",                                       /* 35) COL_NUMBER */
    "%L",                                       /* 36) COL_PACKET_LENGTH */
    "%p",                                       /* 37) COL_PROTOCOL */
    "%Rt",                                      /* 38) COL_REL_TIME */
    "%s",                                       /* 39) COL_DEF_SRC */
    "%S",                                       /* 40) COL_DEF_SRC_PORT */
    "%rs",                                      /* 41) COL_RES_SRC */
    "%us",                                      /* 42) COL_UNRES_SRC */
    "%rS",                                      /* 43) COL_RES_SRC_PORT */
    "%uS",                                      /* 44) COL_UNRES_SRC_PORT */
    "%E",                                       /* 45) COL_TEI */
    "%Yut",                                     /* 46) COL_UTC_YMD_TIME */
    "%YDOYut",                                  /* 47) COL_UTC_YDOY_TIME */
    "%Aut",                                     /* 48) COL_UTC_TIME */
    "%t"                                        /* 49) COL_CLS_TIME */
  };

 /* The following formats have been used in deprecated columns.  Noted here
  * so they aren't reused
  *
  *  "%U",                                             COL_COS_VALUE
  *  "%c",                                             COL_CIRCUIT_ID
  *  "%l",                                             COL_BSSGP_TLLI
  *  "%H",                                             COL_HPUX_SUBSYS
  *  "%P",                                             COL_HPUX_DEVID
  *  "%C",                                             COL_FR_DLCI
  *  "%rct",                                           COL_REL_CONV_TIME
  *  "%dct",                                           COL_DELTA_CONV_TIME
  *  "%XO",                                            COL_OXID
  *  "%XR",                                            COL_RXID
  *  "%Xd",                                            COL_SRCIDX
  *  "%Xs",                                            COL_DSTIDX
  *  "%z",                                             COL_DCE_CTX
  */
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
    "Cisco VSAN",                               /* 4) COL_VSAN */
    "Cumulative Bytes" ,                        /* 5) COL_CUMULATIVE_BYTES */
    "Custom",                                   /* 6) COL_CUSTOM */
    "DCE/RPC call (cn_call_id / dg_seqnum)",    /* 7) COL_DCE_CALL */
    "Delta time",                               /* 8) COL_DELTA_TIME */
    "Delta time displayed",                     /* 9) COL_DELTA_TIME_DIS */
    "Dest addr (resolved)",                     /* 10) COL_RES_DST */
    "Dest addr (unresolved)",                   /* 11) COL_UNRES_DST */
    "Dest port (resolved)",                     /* 12) COL_RES_DST_PORT */
    "Dest port (unresolved)",                   /* 13) COL_UNRES_DST_PORT */
    "Destination address",                      /* 14) COL_DEF_DST */
    "Destination port",                         /* 15) COL_DEF_DST_PORT */
    "Expert Info Severity",                     /* 16) COL_EXPERT */
    "FW-1 monitor if/direction",                /* 17) COL_IF_DIR */
    "Frequency/Channel",                        /* 18) COL_FREQ_CHAN */
    "Hardware dest addr",                       /* 19) COL_DEF_DL_DST */
    "Hardware src addr",                        /* 20) COL_DEF_DL_SRC */
    "Hw dest addr (resolved)",                  /* 21) COL_RES_DL_DST */
    "Hw dest addr (unresolved)",                /* 22) COL_UNRES_DL_DST */
    "Hw src addr (resolved)",                   /* 23) COL_RES_DL_SRC*/
    "Hw src addr (unresolved)",                 /* 24) COL_UNRES_DL_SRC */
    "IEEE 802.11 RSSI",                         /* 25) COL_RSSI */
    "IEEE 802.11 TX rate",                      /* 26) COL_TX_RATE */
    "IP DSCP Value",                            /* 27) COL_DSCP_VALUE */
    "Information",                              /* 28) COL_INFO */
    "Net dest addr (resolved)",                 /* 29) COL_RES_NET_DST */
    "Net dest addr (unresolved)",               /* 30) COL_UNRES_NET_DST */
    "Net src addr (resolved)",                  /* 31) COL_RES_NET_SRC */
    "Net src addr (unresolved)",                /* 32) COL_UNRES_NET_SRC */
    "Network dest addr",                        /* 33) COL_DEF_NET_DST */
    "Network src addr",                         /* 34) COL_DEF_NET_SRC */
    "Number",                                   /* 35) COL_NUMBER */
    "Packet length (bytes)" ,                   /* 36) COL_PACKET_LENGTH */
    "Protocol",                                 /* 37) COL_PROTOCOL */
    "Relative time",                            /* 38) COL_REL_TIME */
    "Source address",                           /* 39) COL_DEF_SRC */
    "Source port",                              /* 40) COL_DEF_SRC_PORT */
    "Src addr (resolved)",                      /* 41) COL_RES_SRC */
    "Src addr (unresolved)",                    /* 42) COL_UNRES_SRC */
    "Src port (resolved)",                      /* 43) COL_RES_SRC_PORT */
    "Src port (unresolved)",                    /* 44) COL_UNRES_SRC_PORT */
    "TEI",                                      /* 45) COL_TEI */
    "UTC date, as YYYY-MM-DD, and time",        /* 46) COL_UTC_YMD_TIME */
    "UTC date, as YYYY/DOY, and time",          /* 47) COL_UTC_YDOY_TIME */
    "UTC time",                                 /* 48) COL_UTC_TIME */
    "Time (format as specified)"                /* 49) COL_CLS_TIME */
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
            case(TS_PREC_FIXED_SEC):
                return "0000-00-00 00:00:00";
                break;
            case(TS_PREC_FIXED_DSEC):
                return "0000-00-00 00:00:00.0";
                break;
            case(TS_PREC_FIXED_CSEC):
                return "0000-00-00 00:00:00.00";
                break;
            case(TS_PREC_FIXED_MSEC):
                return "0000-00-00 00:00:00.000";
                break;
            case(TS_PREC_FIXED_USEC):
                return "0000-00-00 00:00:00.000000";
                break;
            case(TS_PREC_FIXED_NSEC):
            case(TS_PREC_AUTO):    /* Leave enough room for the maximum */
                return "0000-00-00 00:00:00.000000000";
                break;
            default:
                g_assert_not_reached();
        }
            break;
    case(TS_ABSOLUTE_WITH_YDOY):
    case(TS_UTC_WITH_YDOY):
        switch(precision) {
            case(TS_PREC_FIXED_SEC):
                return "0000/000 00:00:00";
                break;
            case(TS_PREC_FIXED_DSEC):
                return "0000/000 00:00:00.0";
                break;
            case(TS_PREC_FIXED_CSEC):
                return "0000/000 00:00:00.00";
                break;
            case(TS_PREC_FIXED_MSEC):
                return "0000/000 00:00:00.000";
                break;
            case(TS_PREC_FIXED_USEC):
                return "0000/000 00:00:00.000000";
                break;
            case(TS_PREC_FIXED_NSEC):
            case(TS_PREC_AUTO):    /* Leave enough room for the maximum */
                return "0000/000 00:00:00.000000000";
                break;
            default:
                g_assert_not_reached();
        }
            break;
    case(TS_ABSOLUTE):
    case(TS_UTC):
        switch(precision) {
            case(TS_PREC_FIXED_SEC):
                return "00:00:00";
                break;
            case(TS_PREC_FIXED_DSEC):
                return "00:00:00.0";
                break;
            case(TS_PREC_FIXED_CSEC):
                return "00:00:00.00";
                break;
            case(TS_PREC_FIXED_MSEC):
                return "00:00:00.000";
                break;
            case(TS_PREC_FIXED_USEC):
                return "00:00:00.000000";
                break;
            case(TS_PREC_FIXED_NSEC):
            case(TS_PREC_AUTO):    /* Leave enough room for the maximum */
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
            case(TS_PREC_FIXED_SEC):
                return "0000";
                break;
            case(TS_PREC_FIXED_DSEC):
                return "0000.0";
                break;
            case(TS_PREC_FIXED_CSEC):
                return "0000.00";
                break;
            case(TS_PREC_FIXED_MSEC):
                return "0000.000";
                break;
            case(TS_PREC_FIXED_USEC):
                return "0000.000000";
                break;
            case(TS_PREC_FIXED_NSEC):
            case(TS_PREC_AUTO):    /* Leave enough room for the maximum */
                return "0000.000000000";
                break;
            default:
                g_assert_not_reached();
        }
        break;
    case(TS_EPOCH):
        /* This is enough to represent 2^63 (signed 64-bit integer) + fractions */
        switch(precision) {
            case(TS_PREC_FIXED_SEC):
                return "0000000000000000000";
                break;
            case(TS_PREC_FIXED_DSEC):
                return "0000000000000000000.0";
                break;
            case(TS_PREC_FIXED_CSEC):
                return "0000000000000000000.00";
                break;
            case(TS_PREC_FIXED_MSEC):
                return "0000000000000000000.000";
                break;
            case(TS_PREC_FIXED_USEC):
                return "0000000000000000000.000000";
                break;
            case(TS_PREC_FIXED_NSEC):
            case(TS_PREC_AUTO):    /* Leave enough room for the maximum */
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
static const char *
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
    case COL_IF_DIR:
      return "i 00000000 I";
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
    case COL_DCE_CALL:
      return "0000";
      break;
    case COL_8021Q_VLAN_ID:
      return "0000";
      break;
    case COL_DSCP_VALUE:
      return "AAA BBB";    /* not the longest, but the longest is too long */
      break;
    case COL_TEI:
      return "127";
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
get_column_custom_fields(const gint col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return NULL;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_fields);
}

void
set_column_custom_fields(const gint col, const char *custom_fields)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->custom_fields);
  cfmt->custom_fields = g_strdup (custom_fields);
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

static gchar *
get_custom_field_tooltip (gchar *custom_field, gint occurrence)
{
    header_field_info *hfi = proto_registrar_get_byname(custom_field);
    if (hfi == NULL) {
        /* Not a valid field */
        return g_strdup_printf("Unknown Field: %s", custom_field);
    }

    if (hfi->parent == -1) {
        /* Protocol */
        return g_strdup_printf("%s (%s)", hfi->name, hfi->abbrev);
    }

    if (occurrence == 0) {
        /* All occurrences */
        return g_strdup_printf("%s\n%s (%s)", proto_get_protocol_name(hfi->parent), hfi->name, hfi->abbrev);
    }

    /* One given occurence */
    return g_strdup_printf("%s\n%s (%s#%d)", proto_get_protocol_name(hfi->parent), hfi->name, hfi->abbrev, occurrence);
}

gchar *
get_column_tooltip(const gint col)
{
    GList    *clp = g_list_nth(prefs.col_list, col);
    fmt_data *cfmt;
    gchar   **fields;
    gboolean  first = TRUE;
    GString  *column_tooltip;
    guint     i;

    if (!clp)  /* Invalid column requested */
        return NULL;

    cfmt = (fmt_data *) clp->data;

    if (cfmt->fmt != COL_CUSTOM) {
        /* Use format description */
        return g_strdup(col_format_desc(cfmt->fmt));
    }

    fields = g_regex_split_simple(COL_CUSTOM_PRIME_REGEX, cfmt->custom_fields,
                                  G_REGEX_ANCHORED, G_REGEX_MATCH_ANCHORED);
    column_tooltip = g_string_new("");

    for (i = 0; i < g_strv_length(fields); i++) {
        if (fields[i] && *fields[i]) {
            gchar *field_tooltip = get_custom_field_tooltip(fields[i], cfmt->custom_occurrence);
            if (!first) {
                g_string_append(column_tooltip, "\n\nOR\n\n");
            }
            g_string_append(column_tooltip, field_tooltip);
            g_free (field_tooltip);
            first = FALSE;
        }
    }

    g_strfreev(fields);

    return g_string_free (column_tooltip, FALSE);
}

void
build_column_format_array(column_info *cinfo, const gint num_cols, const gboolean reset_fences)
{
  int i;
  col_item_t* col_item;

  /* Build the column format array */
  col_setup(cinfo, num_cols);

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];
    col_item->col_fmt = get_column_format(i);
    col_item->col_title = g_strdup(get_column_title(i));

    if (col_item->col_fmt == COL_CUSTOM) {
      col_item->col_custom_fields = g_strdup(get_column_custom_fields(i));
      col_item->col_custom_occurrence = get_column_custom_occurrence(i);
      if(!dfilter_compile(col_item->col_custom_fields, &col_item->col_custom_dfilter, NULL)) {
        /* XXX: Should we issue a warning? */
        g_free(col_item->col_custom_fields);
        col_item->col_custom_fields = NULL;
        col_item->col_custom_occurrence = 0;
        col_item->col_custom_dfilter = NULL;
      }
      if (col_item->col_custom_fields) {
        gchar **fields = g_regex_split(cinfo->prime_regex, col_item->col_custom_fields,
                                       G_REGEX_MATCH_ANCHORED);
        guint i_field;

        for (i_field = 0; i_field < g_strv_length(fields); i_field++) {
          if (fields[i_field] && *fields[i_field]) {
            header_field_info *hfinfo = proto_registrar_get_byname(fields[i_field]);
            if (hfinfo) {
              int *idx = g_new(int, 1);
              *idx = hfinfo->id;
              col_item->col_custom_fields_ids = g_slist_append(col_item->col_custom_fields_ids, idx);
            }
          }
        }
        g_strfreev(fields);
      }
    } else {
      col_item->col_custom_fields = NULL;
      col_item->col_custom_occurrence = 0;
      col_item->col_custom_dfilter = NULL;
    }

    col_item->fmt_matx = (gboolean *) g_malloc0(sizeof(gboolean) * NUM_COL_FMTS);
    get_column_format_matches(col_item->fmt_matx, col_item->col_fmt);
    col_item->col_data = NULL;

    if (col_item->col_fmt == COL_INFO)
      col_item->col_buf = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      col_item->col_buf = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);

    if(reset_fences)
      col_item->col_fence = 0;

    cinfo->col_expr.col_expr[i] = "";
    cinfo->col_expr.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  cinfo->col_expr.col_expr[i] = NULL;
  cinfo->col_expr.col_expr_val[i] = NULL;

  for (i = 0; i < cinfo->num_cols; i++) {
    int j;

    for (j = 0; j < NUM_COL_FMTS; j++) {
      if (!cinfo->columns[i].fmt_matx[j])
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


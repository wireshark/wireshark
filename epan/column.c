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
#include <epan/column.h>
#include <epan/packet.h>

/* Given a format number (as defined in packet.h), returns its equivalent
   string */
const gchar *
col_format_to_string(gint fmt) {
  const gchar *slist[] = {
	"%m", "%t", "%Rt", "%At", "%Yt", "%Tt", "%s", "%rs",
	"%us","%hs", "%rhs", "%uhs", "%ns", "%rns", "%uns", "%d",
	"%rd", "%ud", "%hd", "%rhd", "%uhd", "%nd", "%rnd",
	"%und", "%S", "%rS", "%uS", "%D", "%rD", "%uD", "%p",
	"%i", "%L", "%B", "%XO", "%XR", "%I", "%c", "%Xs", 
	"%Xd", "%V", "%x", "%e", "%H", "%P", "%y", "%v", "%E"
};
                     
  if (fmt < 0 || fmt >= NUM_COL_FMTS)
    return NULL;

  return(slist[fmt]);
}

/* Given a format number (as defined in packet.h), returns its
  description */
static const gchar *dlist[NUM_COL_FMTS] = {
	"Number",
	"Time (format as specified)",
	"Relative time",
	"Absolute time",
	"Absolute date and time",
	"Delta time",
	"Source address",
	"Src addr (resolved)",
	"Src addr (unresolved)",
	"Hardware src addr",
	"Hw src addr (resolved)",
	"Hw src addr (unresolved)",
	"Network src addr",
	"Net src addr (resolved)",
	"Net src addr (unresolved)",
	"Destination address",
	"Dest addr (resolved)",
	"Dest addr (unresolved)",
	"Hardware dest addr",
	"Hw dest addr (resolved)",
	"Hw dest addr (unresolved)",
	"Network dest addr",
	"Net dest addr (resolved)",
	"Net dest addr (unresolved)",
	"Source port",
	"Src port (resolved)",
	"Src port (unresolved)",
	"Destination port",
	"Dest port (resolved)",
	"Dest port (unresolved)",
	"Protocol",
	"Information",
	"Packet length (bytes)" ,
	"Cumulative Bytes" ,
	"Fibre Channel OXID",
	"Fibre Channel RXID",
	"FW-1 monitor if/direction",
	"Circuit ID",
	"Cisco Src PortIdx",
	"Cisco Dst PortIdx",
	"Cisco VSAN",
	"IEEE 802.11 TX rate",
	"IEEE 802.11 RSSI",
	"HP-UX Subsystem",
	"HP-UX Device ID",
	"DCE/RPC call (cn_call_id / dg_seqnum)",
       "802.1Q VLAN id",
	"TEI",
};

const gchar *
col_format_desc(gint fmt) {
  g_assert((fmt >= 0) && (fmt < NUM_COL_FMTS));
  return(dlist[fmt]);
}

/* Marks each array element true if it can be substituted for the given
   column format */
void
get_column_format_matches(gboolean *fmt_list, gint format) {

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
    case COL_8021Q_VLAN_ID:
      fmt_list[COL_8021Q_VLAN_ID] = TRUE;
      break;
    case COL_TEI:
      fmt_list[COL_TEI] = TRUE;
      break;
    default:
      break;
  }
}

/* Returns a string representing the longest possible value for 
   a timestamp column type. */
static const char *
get_timestamp_column_longest_string(gint type, gint precision)
{

	switch(type) {
	case(TS_ABSOLUTE_WITH_DATE):
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
	case(TS_RELATIVE):	/* fallthrough */
	case(TS_DELTA):
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
   particular column type.

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
get_column_longest_string(gint format)
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
    case COL_ABS_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE, timestamp_get_precision());
      break;
    case COL_REL_TIME:
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
      break;
    case COL_DELTA_TIME:
      return get_timestamp_column_longest_string(TS_DELTA, timestamp_get_precision());
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
      return "Protocol";	/* not the longest, but the longest is too long */
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
    case COL_8021Q_VLAN_ID:
      return "0000";
      break;
    case COL_TEI:
      return "127";
      break;
    default: /* COL_INFO */
      return "Source port: kerberos-master  Destination port: kerberos-master";
      break;
  }
}

/* Returns the longest possible width, in characters, for a particular
   column type. */
gint
get_column_char_width(gint format)
{
  return strlen(get_column_longest_string(format));
}

#define TIME_DEF      0
#define TIME_REL      1
#define TIME_ABS      2
#define DATE_TIME_ABS 3
#define TIME_DEL      4

#define RES_DEF  0
#define RES_DO   1
#define RES_DONT 2

#define ADDR_DEF 0
#define ADDR_DL  3
#define ADDR_NET 6

gint
get_column_format(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  cfmt = (fmt_data *) clp->data;

  return(get_column_format_from_str(cfmt->fmt));
}

gint
get_column_format_from_str(gchar *str) {
  gchar *cptr = str;
  gint      res_off = RES_DEF, addr_off = ADDR_DEF, time_off = TIME_DEF;
  gint      prev_code = -1;

  /* To do: Make this parse %-formatted strings "for real" */
  while (*cptr != '\0') {
    switch (*cptr) {
      case 't':  /* To do: fix for absolute and delta */
        return COL_CLS_TIME + time_off;
        break;
      case 'm':
        return COL_NUMBER;
        break;
      case 's':
        if (prev_code == COL_OXID) {
          return COL_SRCIDX;
        }
        else {
          return COL_DEF_SRC + res_off + addr_off;
        }
        break;
      case 'd':
        if (prev_code == COL_OXID) {
          return COL_DSTIDX;
        }
        else {
          return COL_DEF_DST + res_off + addr_off;
        }
        break;
      case 'S':
        return COL_DEF_SRC_PORT + res_off;
        break;
      case 'D':
        return COL_DEF_DST_PORT + res_off;
        break;
      case 'p':
        return COL_PROTOCOL;
        break;
      case 'i':
        return COL_INFO;
        break;
      case 'r':
        res_off = RES_DO;
        break;
      case 'u':
        res_off = RES_DONT;
        break;
      case 'h':
        addr_off = ADDR_DL;
        break;
      case 'n':
        addr_off = ADDR_NET;
        break;
      case 'R':
        if (prev_code == COL_OXID) {
            return COL_RXID;
        }
        else {
            time_off = TIME_REL;
        }
        break;
      case 'A':
        time_off = TIME_ABS;
        break;
      case 'Y':
        time_off = DATE_TIME_ABS;
        break;
      case 'T':
        time_off = TIME_DEL;
        break;
      case 'L':
        return COL_PACKET_LENGTH;
        break;
      case 'B':
        return COL_CUMULATIVE_BYTES;
        break;
      case 'X':
        prev_code = COL_OXID;
        break;
      case 'O':
        return COL_OXID;
        break;
      case 'I':
        return COL_IF_DIR;
        break;
      case 'c':
        return COL_CIRCUIT_ID;
        break;
      case 'V':
        return COL_VSAN;
        break;
      case 'x':
        return COL_TX_RATE;
        break;
      case 'e':
        return COL_RSSI;
        break;
      case 'H':
	return COL_HPUX_SUBSYS;
	break;
      case 'P':
	return COL_HPUX_DEVID;
	break;
      case 'y':
	return COL_DCE_CALL;
	break;
      case 'v':
	return COL_8021Q_VLAN_ID;
	break;
      case 'E':
	return COL_TEI;
	break;
    }
    cptr++;
  }
  return -1;	/* illegal */
}

gchar *
get_column_title(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);
}

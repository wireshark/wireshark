/* column.c
 * Routines for handling column preferences
 *
 * $Id: column.c,v 1.32 2001/07/22 21:28:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "timestamp.h"
#include "prefs.h"
#include "column.h"
#include "packet.h"

/* Given a format number (as defined in packet.h), returns its equivalent
   string */
gchar *
col_format_to_string(gint fmt) {
  gchar *slist[] = { "%m", "%t", "%Rt", "%At", "%Yt", "%Tt", "%s", "%rs",
                     "%us","%hs", "%rhs", "%uhs", "%ns", "%rns", "%uns", "%d",
                     "%rd", "%ud", "%hd", "%rhd", "%uhd", "%nd", "%rnd",
                     "%und", "%S", "%rS", "%uS", "%D", "%rD", "%uD", "%p",
                     "%i", "%L" };
  
  if (fmt < 0 || fmt > NUM_COL_FMTS)
    return NULL;
  
  return(slist[fmt]);
}

/* Given a format number (as defined in packet.h), returns its
  description */
gchar *
col_format_desc(gint fmt) {
  gchar *dlist[] = { "Number", "Time (command line specified)",
                     "Relative time", "Absolute time",
		     "Absolute date and time", "Delta time",
                     "Source address", "Src addr (resolved)",
                     "Src addr (unresolved)", "Hardware src addr",
                     "Hw src addr (resolved)", "Hw src addr (unresolved)",
                     "Network src addr", "Net src addr (resolved)",
                     "Net src addr (unresolved)", "Destination address",
                     "Dest addr (resolved)", "Dest addr (unresolved)",
                     "Hardware dest addr", "Hw dest addr (resolved)",
                     "Hw dest addr (unresolved)", "Network dest addr",
                     "Net dest addr (resolved)", "Net dest addr (unresolved)",
                     "Source port", "Src port (resolved)",
                     "Src port (unresolved)", "Destination port",
                     "Dest port (resolved)", "Dest port (unresolved)",
                     "Protocol", "Information", "Packet length (bytes)" };
  
  if (fmt < 0 || fmt > NUM_COL_FMTS)
    return NULL;
  
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
    default:
      break;
  }
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
char *
get_column_longest_string(gint format)
{
  switch (format) {
    case COL_NUMBER:
      return "0000000";
      break;
    case COL_CLS_TIME:
      if (timestamp_type == ABSOLUTE)
        return "00:00:00.000000";
      else if (timestamp_type == ABSOLUTE_WITH_DATE)
        return "0000-00-00 00:00:00.000000";
      else
        return "0000.000000";
      break;
    case COL_ABS_TIME:
      return "00:00:00.000000";
      break;
    case COL_ABS_DATE_TIME:
      return "0000-00-00 00:00:00.000000";
      break;
    case COL_REL_TIME:
    case COL_DELTA_TIME:
      return "0000.000000";
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
      return "NetBIOS";	/* not the longest, but the longest is too long */
      break;
    case COL_PACKET_LENGTH:
      return "000000";
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

enum col_resize_type
get_column_resize_type(gint format) {
  switch (format) {
    case COL_NUMBER:
    case COL_CLS_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:
    case COL_REL_TIME:
    case COL_DELTA_TIME:
    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
    case COL_PROTOCOL:
    case COL_PACKET_LENGTH:
      /* We don't want these to resize during a live capture, as that
         gets in the way of trying to look at the data while it's being
	 captured. */
      return (RESIZE_AUTO);
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
      /* We don't want these to resize dynamically; if they get resolved
         to names, those names could be very long, and auto-resizing
	 columns showing those names may leave too little room for
	 other columns such as the "Info" column. */
      return (RESIZE_MANUAL);
      break;
    default: /* COL_INFO */
      /* We want this to resize dynamically, even during a live capture,
         because otherewise you won't be able to see all that's in
	 it. */
      return (RESIZE_LIVE);
      break;
  }
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
        return COL_DEF_SRC + res_off + addr_off;
        break;
      case 'd':
        return COL_DEF_DST + res_off + addr_off;
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
        time_off = TIME_REL;
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
    }
    cptr++;
  }
  return COL_NUMBER;
}

gchar *
get_column_title(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;
  
  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);  
}

/* XXX - needs to handle quote marks inside the quoted string, by
   backslash-escaping them.

   XXX - does this really belong in "prefs.c", instead, as it has to know
   about the syntax of the preferences file? */
#define MAX_FMT_PREF_LEN      1024
#define MAX_FMT_PREF_LINE_LEN   60
gchar *
col_format_to_pref_str(void) {
  static gchar  pref_str[MAX_FMT_PREF_LEN] = "";
  GList        *clp = g_list_first(prefs.col_list);
  fmt_data     *cfmt;
  int           cur_pos = 0, cur_len = 0, fmt_len;
  
  while (clp) {
    cfmt = (fmt_data *) clp->data;
    
    fmt_len = strlen(cfmt->title) + 4;
    if ((fmt_len + cur_len) < (MAX_FMT_PREF_LEN - 1)) {
      if ((fmt_len + cur_pos) > MAX_FMT_PREF_LINE_LEN) {
        cur_len--;
        cur_pos = 0;
	        pref_str[cur_len] = '\n'; cur_len++;
        pref_str[cur_len] = '\t'; cur_len++;
      }
      sprintf(&pref_str[cur_len], "\"%s\", ", cfmt->title);
      cur_len += fmt_len;
      cur_pos += fmt_len;
    }

    fmt_len = strlen(cfmt->fmt) + 4;
    if ((fmt_len + cur_len) < (MAX_FMT_PREF_LEN - 1)) {
      if ((fmt_len + cur_pos) > MAX_FMT_PREF_LINE_LEN) {
        cur_len--;
        cur_pos = 0;
        pref_str[cur_len] = '\n'; cur_len++;
        pref_str[cur_len] = '\t'; cur_len++;
      }
      sprintf(&pref_str[cur_len], "\"%s\", ", cfmt->fmt);
      cur_len += fmt_len;
      cur_pos += fmt_len;
    }
    
    clp = clp->next;
  }
  
  if (cur_len > 2)
    pref_str[cur_len - 2] = '\0';

  return(pref_str);
}    

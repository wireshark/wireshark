/* column-utils.c
 * Routines for column utilities.
 *
 * $Id: column-utils.c,v 1.3 2001/04/02 10:38:26 guy Exp $
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

#include <string.h>
#include <time.h>

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#include "column-utils.h"
#include "timestamp.h"
#include "sna-utils.h"
#include "atalk-utils.h"
#include "to_str.h"
#include "packet_info.h"
#include "pint.h"
#include "resolv.h"
#include "ipv6-utils.h" 
#include "osi-utils.h"

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void
col_init(column_info *col_info, gint num_cols)
{
  col_info->num_cols	= num_cols;
  col_info->col_fmt	= (gint *) g_malloc(sizeof(gint) * num_cols);
  col_info->fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * num_cols);
  col_info->col_width	= (gint *) g_malloc(sizeof(gint) * num_cols);
  col_info->col_title	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
  col_info->col_data	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
  col_info->col_buf	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
}

/*
 * This function does not appear to be used anywhere...  

gboolean
col_get_writable(frame_data *fd)
{
  if (fd) {

    return (fd->cinfo ? fd->cinfo->writable : FALSE);

  }

  return FALSE;

}

*/

void
col_set_writable(frame_data *fd, gboolean writable)
{
	if (fd->cinfo) {
		fd->cinfo->writable = writable;
	}
}

/* Checks to see if a particular packet information element is needed for
   the packet list */
gint
check_col(frame_data *fd, gint el) {
  int i;

  if (fd->cinfo && fd->cinfo->writable) {
    for (i = 0; i < fd->cinfo->num_cols; i++) {
      if (fd->cinfo->fmt_matx[i][el])
        return TRUE;
    }
  }
  return FALSE;
}



/* Use this to clear out a column, especially if you're going to be
   appending to it later; at least on some platforms, it's more
   efficient than using "col_add_str()" with a null string, and
   more efficient than "col_set_str()" with a null string if you
   later append to it, as the later append will cause a string
   copy to be done. */
void
col_clear(frame_data *fd, gint el) {
  int    i;

  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      fd->cinfo->col_buf[i][0] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(frame_data *fd, gint el, gchar* str) {
  int i;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el])
      fd->cinfo->col_data[i] = str;
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(frame_data *fd, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      vsnprintf(fd->cinfo->col_buf[i], max_len, format, ap);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Appends a vararg list to a packet info string. */
void
col_append_fstr(frame_data *fd, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  len, max_len;
  
  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      if (fd->cinfo->col_data[i] != fd->cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(fd->cinfo->col_buf[i], fd->cinfo->col_data[i], max_len);
	fd->cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(fd->cinfo->col_buf[i]);
      vsnprintf(&fd->cinfo->col_buf[i][len], max_len - len, format, ap);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(frame_data *fd, gint el, const gchar* str) {
  int    i;
  size_t max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      strncpy(fd->cinfo->col_buf[i], str, max_len);
      fd->cinfo->col_buf[i][max_len - 1] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

void
col_append_str(frame_data *fd, gint el, gchar* str) {
  int    i;
  size_t len, max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      if (fd->cinfo->col_data[i] != fd->cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(fd->cinfo->col_buf[i], fd->cinfo->col_data[i], max_len);
	fd->cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(fd->cinfo->col_buf[i]);
      strncat(fd->cinfo->col_buf[i], str, max_len - len);
      fd->cinfo->col_buf[i][max_len - 1] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

static void
col_set_abs_date_time(frame_data *fd, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN,
    "%04d-%02d-%02d %02d:%02d:%02d.%04ld",
    tmp->tm_year + 1900,
    tmp->tm_mon + 1,
    tmp->tm_mday,
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec,
    (long)fd->abs_usecs/100);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

static void
col_set_rel_time(frame_data *fd, int col)
{
  display_signed_time(fd->cinfo->col_buf[col], COL_MAX_LEN,
	fd->rel_secs, fd->rel_usecs);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

static void
col_set_delta_time(frame_data *fd, int col)
{
  display_signed_time(fd->cinfo->col_buf[col], COL_MAX_LEN,
	fd->del_secs, fd->del_usecs);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

/* To do: Add check_col checks to the col_add* routines */

static void
col_set_abs_time(frame_data *fd, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%02d:%02d:%02d.%04ld",
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec,
    (long)fd->abs_usecs/100);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

/* Add "command-line-specified" time.
   XXX - this is called from "file.c" when the user changes the time
   format they want for "command-line-specified" time; it's a bit ugly
   that we have to export it, but if we go to a CList-like widget that
   invokes callbacks to get the text for the columns rather than
   requiring us to stuff the text into the widget from outside, we
   might be able to clean this up. */
void
col_set_cls_time(frame_data *fd, int col)
{
  switch (timestamp_type) {
    case ABSOLUTE:
      col_set_abs_time(fd, col);
      break;

    case ABSOLUTE_WITH_DATE:
      col_set_abs_date_time(fd, col);
      break;

    case RELATIVE:
      col_set_rel_time(fd, col);
      break;

    case DELTA:
      col_set_delta_time(fd, col);
      break;
  }
}

static void
col_set_addr(frame_data *fd, int col, address *addr, gboolean is_res)
{
  guint32 ipv4_addr;
  struct e_in6_addr ipv6_addr;
  struct atalk_ddp_addr ddp_addr;
  struct sna_fid_type_4_addr sna_fid_type_4_addr;

  switch (addr->type) {

  case AT_ETHER:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_ether_name(addr->data), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ether_to_str(addr->data), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPv4:
    memcpy(&ipv4_addr, addr->data, sizeof ipv4_addr);
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_hostname(ipv4_addr), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ip_to_str(addr->data), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPv6:
    memcpy(&ipv6_addr.s6_addr, addr->data, sizeof ipv6_addr.s6_addr);
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_hostname6(&ipv6_addr), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ip6_to_str(&ipv6_addr), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPX:
    strncpy(fd->cinfo->col_buf[col],
      ipx_addr_to_str(pntohl(&addr->data[0]), &addr->data[4]), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_SNA:
    switch (addr->len) {

    case 1:
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%04X", addr->data[0]);
      break;

    case 2:
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%04X",
        pntohs(&addr->data[0]));
      break;

    case SNA_FID_TYPE_4_ADDR_LEN:
      memcpy(&sna_fid_type_4_addr, addr->data, SNA_FID_TYPE_4_ADDR_LEN);
      strncpy(fd->cinfo->col_buf[col],
        sna_fid_type_4_addr_to_str(&sna_fid_type_4_addr), COL_MAX_LEN);
      break;
    }
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_ATALK:
    memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
    strncpy(fd->cinfo->col_buf[col], atalk_addr_to_str(&ddp_addr),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_VINES:
    strncpy(fd->cinfo->col_buf[col], vines_addr_to_str(&addr->data[0]),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_OSI:
    strncpy(fd->cinfo->col_buf[col], print_nsap_net(addr->data, addr->len),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  default:
    break;
  }
}

static void
col_set_port(frame_data *fd, int col, port_type ptype, guint32 port,
		gboolean is_res)
{
  switch (ptype) {

  case PT_SCTP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_sctp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;
    
  case PT_TCP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_tcp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  case PT_UDP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_udp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  default:
    break;
  }
  fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

void
fill_in_columns(frame_data *fd)
{
  int i;

  for (i = 0; i < fd->cinfo->num_cols; i++) {
    switch (fd->cinfo->col_fmt[i]) {

    case COL_NUMBER:
      snprintf(fd->cinfo->col_buf[i], COL_MAX_LEN, "%u", fd->num);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
      break;

    case COL_CLS_TIME:
      col_set_cls_time(fd, i);
      break;

    case COL_ABS_TIME:
      col_set_abs_time(fd, i);
      break;

    case COL_ABS_DATE_TIME:
      col_set_abs_date_time(fd, i);
      break;

    case COL_REL_TIME:
      col_set_rel_time(fd, i);
      break;

    case COL_DELTA_TIME:
      col_set_delta_time(fd, i);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:	/* COL_DEF_SRC is currently just like COL_RES_SRC */
      col_set_addr(fd, i, &pi.src, TRUE);
      break;

    case COL_UNRES_SRC:
      col_set_addr(fd, i, &pi.src, FALSE);
      break;

    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
      col_set_addr(fd, i, &pi.dl_src, TRUE);
      break;

    case COL_UNRES_DL_SRC:
      col_set_addr(fd, i, &pi.dl_src, FALSE);
      break;

    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
      col_set_addr(fd, i, &pi.net_src, TRUE);
      break;

    case COL_UNRES_NET_SRC:
      col_set_addr(fd, i, &pi.net_src, FALSE);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:	/* COL_DEF_DST is currently just like COL_RES_DST */
      col_set_addr(fd, i, &pi.dst, TRUE);
      break;

    case COL_UNRES_DST:
      col_set_addr(fd, i, &pi.dst, FALSE);
      break;

    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
      col_set_addr(fd, i, &pi.dl_dst, TRUE);
      break;

    case COL_UNRES_DL_DST:
      col_set_addr(fd, i, &pi.dl_dst, FALSE);
      break;

    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
      col_set_addr(fd, i, &pi.net_dst, TRUE);
      break;

    case COL_UNRES_NET_DST:
      col_set_addr(fd, i, &pi.net_dst, FALSE);
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:	/* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
      col_set_port(fd, i, pi.ptype, pi.srcport, TRUE);
      break;

    case COL_UNRES_SRC_PORT:
      col_set_port(fd, i, pi.ptype, pi.srcport, FALSE);
      break;

    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:	/* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
      col_set_port(fd, i, pi.ptype, pi.destport, TRUE);
      break;

    case COL_UNRES_DST_PORT:
      col_set_port(fd, i, pi.ptype, pi.destport, FALSE);
      break;

    case COL_PROTOCOL:	/* currently done by dissectors */
    case COL_INFO:	/* currently done by dissectors */
      break;

    case COL_PACKET_LENGTH:
      snprintf(fd->cinfo->col_buf[i], COL_MAX_LEN, "%d", fd->pkt_len);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
      break;

    case NUM_COL_FMTS:	/* keep compiler happy - shouldn't get here */
      break;
    }
  }
}
	






/* column-utils.c
 * Routines for column utilities.
 *
 * $Id: column-utils.c,v 1.9 2001/12/10 02:15:54 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <time.h>

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

#if 0
/*
 * This function does not appear to be used anywhere...  
 */
gboolean
col_get_writable(column_info *cinfo)
{
	return (cinfo ? cinfo->writable : FALSE);
}
#endif

void
col_set_writable(column_info *cinfo, gboolean writable)
{
	if (cinfo)
		cinfo->writable = writable;
}

/* Checks to see if a particular packet information element is needed for
   the packet list */
gint
check_col(column_info *cinfo, gint el) {
  int i;

  if (cinfo && cinfo->writable) {
    for (i = 0; i < cinfo->num_cols; i++) {
      if (cinfo->fmt_matx[i][el])
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
col_clear(column_info *cinfo, gint el) {
  int    i;

  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el]) {
      cinfo->col_buf[i][0] = 0;
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(column_info *cinfo, gint el, gchar* str) {
  int i;
  
  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el])
      cinfo->col_data[i] = str;
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(column_info *cinfo, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el]) {
      vsnprintf(cinfo->col_buf[i], max_len, format, ap);
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
}

/* Appends a vararg list to a packet info string. */
void
col_append_fstr(column_info *cinfo, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  len, max_len;
  
  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el]) {
      if (cinfo->col_data[i] != cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(cinfo->col_buf[i], cinfo->col_data[i], max_len);
	cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(cinfo->col_buf[i]);
      vsnprintf(&cinfo->col_buf[i][len], max_len - len, format, ap);
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(column_info *cinfo, gint el, const gchar* str) {
  int    i;
  size_t max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el]) {
      strncpy(cinfo->col_buf[i], str, max_len);
      cinfo->col_buf[i][max_len - 1] = 0;
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
}

void
col_append_str(column_info *cinfo, gint el, gchar* str) {
  int    i;
  size_t len, max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < cinfo->num_cols; i++) {
    if (cinfo->fmt_matx[i][el]) {
      if (cinfo->col_data[i] != cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(cinfo->col_buf[i], cinfo->col_data[i], max_len);
	cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(cinfo->col_buf[i]);
      strncat(cinfo->col_buf[i], str, max_len - len);
      cinfo->col_buf[i][max_len - 1] = 0;
      cinfo->col_data[i] = cinfo->col_buf[i];
    }
  }
}

static void
col_set_abs_date_time(frame_data *fd, column_info *cinfo, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  if (tmp != NULL) {
    snprintf(cinfo->col_buf[col], COL_MAX_LEN,
             "%04d-%02d-%02d %02d:%02d:%02d.%04ld",
             tmp->tm_year + 1900,
             tmp->tm_mon + 1,
             tmp->tm_mday,
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_usecs/100);
  } else {
    cinfo->col_buf[col][0] = '\0';
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

static void
col_set_rel_time(frame_data *fd, column_info *cinfo, int col)
{
  display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
	fd->rel_secs, fd->rel_usecs, USECS);
  cinfo->col_data[col] = cinfo->col_buf[col];
}

static void
col_set_delta_time(frame_data *fd, column_info *cinfo, int col)
{
  display_signed_time(cinfo->col_buf[col], COL_MAX_LEN,
	fd->del_secs, fd->del_usecs, USECS);
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* To do: Add check_col checks to the col_add* routines */

static void
col_set_abs_time(frame_data *fd, column_info *cinfo, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  if (tmp != NULL) {
    snprintf(cinfo->col_buf[col], COL_MAX_LEN, "%02d:%02d:%02d.%04ld",
             tmp->tm_hour,
             tmp->tm_min,
             tmp->tm_sec,
             (long)fd->abs_usecs/100);
  } else {
    cinfo->col_buf[col][0] = '\0';
  }
  cinfo->col_data[col] = cinfo->col_buf[col];
}

/* Add "command-line-specified" time.
   XXX - this is called from "file.c" when the user changes the time
   format they want for "command-line-specified" time; it's a bit ugly
   that we have to export it, but if we go to a CList-like widget that
   invokes callbacks to get the text for the columns rather than
   requiring us to stuff the text into the widget from outside, we
   might be able to clean this up. */
void
col_set_cls_time(frame_data *fd, column_info *cinfo, int col)
{
  switch (timestamp_type) {
    case ABSOLUTE:
      col_set_abs_time(fd, cinfo, col);
      break;

    case ABSOLUTE_WITH_DATE:
      col_set_abs_date_time(fd, cinfo, col);
      break;

    case RELATIVE:
      col_set_rel_time(fd, cinfo, col);
      break;

    case DELTA:
      col_set_delta_time(fd, cinfo, col);
      break;
  }
}

static void
col_set_addr(packet_info *pinfo, int col, address *addr, gboolean is_res)
{
  guint32 ipv4_addr;
  struct e_in6_addr ipv6_addr;
  struct atalk_ddp_addr ddp_addr;
  struct sna_fid_type_4_addr sna_fid_type_4_addr;

  switch (addr->type) {

  case AT_ETHER:
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_ether_name(addr->data), COL_MAX_LEN);
    else
      strncpy(pinfo->cinfo->col_buf[col], ether_to_str(addr->data), COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_IPv4:
    memcpy(&ipv4_addr, addr->data, sizeof ipv4_addr);
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_hostname(ipv4_addr), COL_MAX_LEN);
    else
      strncpy(pinfo->cinfo->col_buf[col], ip_to_str(addr->data), COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_IPv6:
    memcpy(&ipv6_addr.s6_addr, addr->data, sizeof ipv6_addr.s6_addr);
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_hostname6(&ipv6_addr), COL_MAX_LEN);
    else
      strncpy(pinfo->cinfo->col_buf[col], ip6_to_str(&ipv6_addr), COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_IPX:
    strncpy(pinfo->cinfo->col_buf[col],
      ipx_addr_to_str(pntohl(&addr->data[0]), &addr->data[4]), COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_SNA:
    switch (addr->len) {

    case 1:
      snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%04X", addr->data[0]);
      break;

    case 2:
      snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%04X",
        pntohs(&addr->data[0]));
      break;

    case SNA_FID_TYPE_4_ADDR_LEN:
      memcpy(&sna_fid_type_4_addr, addr->data, SNA_FID_TYPE_4_ADDR_LEN);
      strncpy(pinfo->cinfo->col_buf[col],
        sna_fid_type_4_addr_to_str(&sna_fid_type_4_addr), COL_MAX_LEN);
      break;
    }
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_ATALK:
    memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
    strncpy(pinfo->cinfo->col_buf[col], atalk_addr_to_str(&ddp_addr),
      COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_VINES:
    strncpy(pinfo->cinfo->col_buf[col], vines_addr_to_str(&addr->data[0]),
      COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  case AT_OSI:
    strncpy(pinfo->cinfo->col_buf[col], print_nsap_net(addr->data, addr->len),
      COL_MAX_LEN);
    pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
    break;

  default:
    break;
  }
}

static void
col_set_port(packet_info *pinfo, int col, port_type ptype, guint32 port,
		gboolean is_res)
{
  switch (ptype) {

  case PT_SCTP:
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_sctp_port(port), COL_MAX_LEN);
    else
      snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;
    
  case PT_TCP:
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_tcp_port(port), COL_MAX_LEN);
    else
      snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  case PT_UDP:
    if (is_res)
      strncpy(pinfo->cinfo->col_buf[col], get_udp_port(port), COL_MAX_LEN);
    else
      snprintf(pinfo->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  default:
    break;
  }
  pinfo->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
  pinfo->cinfo->col_data[col] = pinfo->cinfo->col_buf[col];
}

void
fill_in_columns(packet_info *pinfo)
{
  int i;

  for (i = 0; i < pinfo->cinfo->num_cols; i++) {
    switch (pinfo->cinfo->col_fmt[i]) {

    case COL_NUMBER:
      snprintf(pinfo->cinfo->col_buf[i], COL_MAX_LEN, "%u", pinfo->fd->num);
      pinfo->cinfo->col_data[i] = pinfo->cinfo->col_buf[i];
      break;

    case COL_CLS_TIME:
      col_set_cls_time(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_ABS_TIME:
      col_set_abs_time(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_ABS_DATE_TIME:
      col_set_abs_date_time(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_REL_TIME:
      col_set_rel_time(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_DELTA_TIME:
      col_set_delta_time(pinfo->fd, pinfo->cinfo, i);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:	/* COL_DEF_SRC is currently just like COL_RES_SRC */
      col_set_addr(pinfo, i, &pinfo->src, TRUE);
      break;

    case COL_UNRES_SRC:
      col_set_addr(pinfo, i, &pinfo->src, FALSE);
      break;

    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
      col_set_addr(pinfo, i, &pinfo->dl_src, TRUE);
      break;

    case COL_UNRES_DL_SRC:
      col_set_addr(pinfo, i, &pinfo->dl_src, FALSE);
      break;

    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
      col_set_addr(pinfo, i, &pinfo->net_src, TRUE);
      break;

    case COL_UNRES_NET_SRC:
      col_set_addr(pinfo, i, &pinfo->net_src, FALSE);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:	/* COL_DEF_DST is currently just like COL_RES_DST */
      col_set_addr(pinfo, i, &pinfo->dst, TRUE);
      break;

    case COL_UNRES_DST:
      col_set_addr(pinfo, i, &pinfo->dst, FALSE);
      break;

    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
      col_set_addr(pinfo, i, &pinfo->dl_dst, TRUE);
      break;

    case COL_UNRES_DL_DST:
      col_set_addr(pinfo, i, &pinfo->dl_dst, FALSE);
      break;

    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
      col_set_addr(pinfo, i, &pinfo->net_dst, TRUE);
      break;

    case COL_UNRES_NET_DST:
      col_set_addr(pinfo, i, &pinfo->net_dst, FALSE);
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:	/* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
      col_set_port(pinfo, i, pinfo->ptype, pinfo->srcport, TRUE);
      break;

    case COL_UNRES_SRC_PORT:
      col_set_port(pinfo, i, pinfo->ptype, pinfo->srcport, FALSE);
      break;

    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:	/* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
      col_set_port(pinfo, i, pinfo->ptype, pinfo->destport, TRUE);
      break;

    case COL_UNRES_DST_PORT:
      col_set_port(pinfo, i, pinfo->ptype, pinfo->destport, FALSE);
      break;

    case COL_PROTOCOL:	/* currently done by dissectors */
    case COL_INFO:	/* currently done by dissectors */
      break;

    case COL_PACKET_LENGTH:
      snprintf(pinfo->cinfo->col_buf[i], COL_MAX_LEN, "%u", pinfo->fd->pkt_len);
      pinfo->cinfo->col_data[i] = pinfo->cinfo->col_buf[i];
      break;

    case NUM_COL_FMTS:	/* keep compiler happy - shouldn't get here */
      g_assert_not_reached();
      break;
    }
  }
}

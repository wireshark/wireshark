/* to_str.h
 * Definitions for utilities to convert various other types to strings.
 *
 * $Id: to_str.h,v 1.5 2001/09/14 07:10:10 guy Exp $
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

#ifndef __TO_STR_H__
#define __TO_STR_H__

#include <glib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "nstime.h"

/*
 * Resolution of a time stamp.
 */
typedef enum {
	MSECS,	/* milliseconds */
	USECS,	/* microseconds */
	NSECS	/* nanoseconds */
} time_res_t;

/* 
 * These are utility functions which convert various types to strings,
 * but for which no more specific module applies.  
 */

gchar*     ether_to_str(const guint8 *);
gchar*     ether_to_str_punct(const guint8 *, char);
gchar*     ip_to_str(const guint8 *);
void       ip_to_str_buf(const guint8 *, gchar *);
struct     e_in6_addr;
gchar*     ip6_to_str(struct e_in6_addr *);
gchar*     ipx_addr_to_str(guint32, const guint8 *);
gchar*     ipxnet_to_string(const guint8 *ad);
gchar*     ipxnet_to_str_punct(const guint32 ad, char punct);
gchar*     vines_addr_to_str(const guint8 *addrp);
gchar*     time_secs_to_str(guint32);
gchar*     time_msecs_to_str(guint32);
gchar*	   abs_time_to_str(nstime_t*);
void       display_signed_time(gchar *, int, gint32, gint32, time_res_t);
gchar*	   rel_time_to_str(nstime_t*);
gchar*	   rel_time_to_secs_str(nstime_t*);


char * decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width);
const char *decode_boolean_bitfield(guint32 val, guint32 mask, int width,
  const char *truedesc, const char *falsedesc);
const char *decode_numeric_bitfield(guint32 val, guint32 mask, int width,
  const char *fmt);

#endif /* __TO_STR_H__  */

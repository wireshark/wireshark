/* to_str.h
 * Definitions for utilities to convert various other types to strings.
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

#ifndef __TO_STR_H__
#define __TO_STR_H__

#include <glib.h>

#include "nstime.h"
#include "epan/packet_info.h"

#define MAX_OID_STR_LEN 256
#define GUID_STR_LEN 37

/*
 * Resolution of a time stamp.
 */
typedef enum {
	SECS,	/* seconds */
	DSECS,	/* deciseconds */
	CSECS,	/* centiseconds */
	MSECS,	/* milliseconds */
	USECS,	/* microseconds */
	NSECS	/* nanoseconds */
} time_res_t;

/*
 * These are utility functions which convert various types to strings,
 * but for which no more specific module applies.
 */

struct     e_in6_addr;

extern gchar*	address_to_str(const address *);
extern void     address_to_str_buf(const address *addr, gchar *buf, int buf_len);
extern gchar*   bytestring_to_str(const guint8 *, guint32, char);
extern gchar*	ether_to_str(const guint8 *);
extern gchar*	ip_to_str(const guint8 *);
extern void	ip_to_str_buf(const guint8 *, gchar *);
extern gchar*	fc_to_str(const guint8 *);
extern gchar*	fcwwn_to_str (const guint8 *);
extern gchar*	ip6_to_str(const struct e_in6_addr *);
extern void	ip6_to_str_buf(const struct e_in6_addr *, gchar *);
extern gchar*	ipx_addr_to_str(guint32, const guint8 *);
extern gchar*	ipxnet_to_string(const guint8 *ad);
extern gchar*	ipxnet_to_str_punct(const guint32 ad, char punct);
extern gchar*	vines_addr_to_str(const guint8 *addrp);
extern void	vines_addr_to_str_buf(const guint8 *addrp, gchar *buf, int buf_len);
extern gchar*	time_secs_to_str(gint32);
extern gchar*	time_msecs_to_str(gint32);
extern gchar*	abs_time_to_str(nstime_t*);
extern gchar*	abs_time_secs_to_str(time_t);
extern void	display_signed_time(gchar *, int, gint32, gint32, time_res_t);
extern gchar*	rel_time_to_str(nstime_t*);
extern gchar*	rel_time_to_secs_str(nstime_t*);
extern gchar*	oid_to_str(const guint8*, gint);
extern gchar*	oid_to_str_buf(const guint8*, gint, gchar*, int);
extern gchar*	guid_to_str(const e_guid_t*);
extern gchar*	guid_to_str_buf(const e_guid_t*, gchar*, int);

void tipc_addr_to_str_buf( const guint8 *data, gchar *buf, int buf_len);

extern char	*other_decode_bitfield_value(char *buf, guint32 val, guint32 mask,
    int width);
extern char	*decode_bitfield_value(char *buf, guint32 val, guint32 mask,
    int width);
extern const char *decode_boolean_bitfield(guint32 val, guint32 mask, int width,
  const char *truedesc, const char *falsedesc);
extern const char *decode_numeric_bitfield(guint32 val, guint32 mask, int width,
  const char *fmt);

#endif /* __TO_STR_H__  */

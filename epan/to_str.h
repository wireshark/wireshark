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
#include "time_fmt.h"
#include <epan/packet_info.h>

#define GUID_STR_LEN 37
#define MAX_IP_STR_LEN 16
#define MAX_IP6_STR_LEN 40
#define MAX_ADDR_STR_LEN 256
#define VINES_ADDR_LEN	6

/*
 * These are utility functions which convert various types to strings,
 * but for which no more specific module applies.
 */

struct     e_in6_addr;

/* !!Deprecated!! - use ep_address_to_str() */
#define address_to_str ep_address_to_str
extern gchar*	ep_address_to_str(const address *);
extern gchar*	se_address_to_str(const address *);
extern void     address_to_str_buf(const address *addr, gchar *buf, int buf_len);
extern gchar*   bytestring_to_str(const guint8 *, const guint32, const char);
extern gchar*	ether_to_str(const guint8 *);
extern gchar*	tvb_ether_to_str(tvbuff_t *tvb, const gint offset);
extern const gchar*	ip_to_str(const guint8 *);
extern const gchar*	tvb_ip_to_str(tvbuff_t *tvb, const gint offset);
extern void	ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len);
extern gchar*	fc_to_str(const guint8 *);
extern gchar*	fcwwn_to_str (const guint8 *);
extern gchar*	tvb_fc_to_str(tvbuff_t *tvb, const gint offset);
extern gchar*	tvb_fcwwn_to_str (tvbuff_t *tvb, const gint offset);
extern gchar*	ip6_to_str(const struct e_in6_addr *);
extern gchar*	tvb_ip6_to_str(tvbuff_t *tvb, const gint offset);
extern void	ip6_to_str_buf(const struct e_in6_addr *, gchar *);
extern gchar*	ipx_addr_to_str(const guint32, const guint8 *);
extern gchar*	ipxnet_to_string(const guint8 *ad);
extern gchar*	ipxnet_to_str_punct(const guint32 ad, const char punct);
extern gchar*	tvb_vines_addr_to_str(tvbuff_t *tvb, const gint offset);
extern gchar*	time_secs_to_str(const gint32 time_val);
extern gchar*	time_secs_to_str_unsigned(const guint32);
extern gchar*	time_msecs_to_str(gint32 time_val);
extern gchar*	abs_time_to_str(const nstime_t*, const absolute_time_display_e fmt,
    gboolean show_zone);
extern gchar*	abs_time_secs_to_str(const time_t, const absolute_time_display_e fmt,
    gboolean show_zone);
extern void	display_signed_time(gchar *, int, const gint32, gint32, const to_str_time_res_t);
extern void	display_epoch_time(gchar *, int, const time_t,  gint32, const to_str_time_res_t);

extern gchar*	guint32_to_str(const guint32 u);
extern void	guint32_to_str_buf(guint32 u, gchar *buf, int buf_len);

extern gchar*	rel_time_to_str(const nstime_t*);
extern gchar*	rel_time_to_secs_str(const nstime_t*);
extern gchar*	guid_to_str(const e_guid_t*);
extern gchar*	guid_to_str_buf(const e_guid_t*, gchar*, int);

extern char *decode_bits_in_field(const gint bit_offset, const gint no_of_bits, const guint64 value);

extern char	*other_decode_bitfield_value(char *buf, const guint32 val, const guint32 mask,
    const int width);
extern char	*decode_bitfield_value(char *buf, const guint32 val, const guint32 mask,
    const int width);
extern const char *decode_boolean_bitfield(const guint32 val, const guint32 mask, const int width,
  const char *truedesc, const char *falsedesc);
extern const char *decode_numeric_bitfield(const guint32 val, const guint32 mask, const int width,
  const char *fmt);

#endif /* __TO_STR_H__  */

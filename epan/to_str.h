/* to_str.h
 * Definitions for utilities to convert various other types to strings.
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

#ifndef __TO_STR_H__
#define __TO_STR_H__

#include <glib.h>

#include "wsutil/nstime.h"
#include "time_fmt.h"
#include <epan/packet_info.h>
#include "ws_symbol_export.h"
#include "wmem/wmem.h"

#define GUID_STR_LEN 37
#define MAX_IP_STR_LEN 16
#define MAX_IP6_STR_LEN 40
#define MAX_ADDR_STR_LEN 256
#define VINES_ADDR_LEN	6
#define EUI64_STR_LEN 24

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * These are utility functions which convert various types to strings,
 * but for which no more specific module applies.
 */

struct     e_in6_addr;

WS_DLL_PUBLIC gchar* address_to_str(wmem_allocator_t *scope, const address *addr);
WS_DLL_PUBLIC gchar* ep_address_to_str(const address *);
WS_DLL_PUBLIC void     address_to_str_buf(const address *addr, gchar *buf, int buf_len);
WS_DLL_PUBLIC const gchar*	ether_to_str(const guint8 *);
WS_DLL_PUBLIC const gchar*	tvb_ether_to_str(tvbuff_t *tvb, const gint offset);
extern const gchar*   ax25_to_str(const guint8 *);
extern gchar*   get_ax25_name(const guint8 *);
WS_DLL_PUBLIC const gchar*	ip_to_str(const guint8 *);
WS_DLL_PUBLIC const gchar*	tvb_ip_to_str(tvbuff_t *tvb, const gint offset);
void	ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len);
extern const gchar*	fc_to_str(const guint8 *);
extern gchar*	fcwwn_to_str (const guint8 *);
WS_DLL_PUBLIC const gchar*	tvb_fc_to_str(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gchar*	tvb_fcwwn_to_str (tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC const gchar*	ip6_to_str(const struct e_in6_addr *);
WS_DLL_PUBLIC const gchar*      ip6_guint8_to_str(const guint8 *ad);

WS_DLL_PUBLIC const gchar*	tvb_ip6_to_str(tvbuff_t *tvb, const gint offset);
void	ip6_to_str_buf(const struct e_in6_addr *, gchar *);
extern gchar*	ipx_addr_to_str(const guint32, const guint8 *);
extern gchar*	ipxnet_to_string(const guint8 *ad);
extern gchar*	tvb_ipxnet_to_string(tvbuff_t *tvb, const gint offset);
extern gchar*	ipxnet_to_str_punct(const guint32 ad, const char punct);
extern gchar*	tvb_vines_addr_to_str(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gchar*	eui64_to_str(const guint64 ad);
WS_DLL_PUBLIC gchar*	tvb_eui64_to_str(tvbuff_t *tvb, const gint offset, const guint encoding);
WS_DLL_PUBLIC gchar*	time_secs_to_str(wmem_allocator_t *scope, const gint32 time_val);
gchar*	time_secs_to_str_unsigned(wmem_allocator_t *scope, const guint32);
WS_DLL_PUBLIC gchar*	time_msecs_to_str(wmem_allocator_t *scope, gint32 time_val);
WS_DLL_PUBLIC gchar*	abs_time_to_str(wmem_allocator_t *scope, const nstime_t*, const absolute_time_display_e fmt,
    gboolean show_zone);
WS_DLL_PUBLIC gchar*	abs_time_secs_to_str(wmem_allocator_t *scope, const time_t, const absolute_time_display_e fmt,
    gboolean show_zone);
WS_DLL_PUBLIC void	display_signed_time(gchar *, int, const gint32, gint32, const to_str_time_res_t);
WS_DLL_PUBLIC void	display_epoch_time(gchar *, int, const time_t,  gint32, const to_str_time_res_t);

extern void	guint32_to_str_buf(guint32 u, gchar *buf, int buf_len);

WS_DLL_PUBLIC gchar*	rel_time_to_str(wmem_allocator_t *scope, const nstime_t*);
WS_DLL_PUBLIC gchar*	rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t*);
WS_DLL_PUBLIC gchar*	guid_to_ep_str(const e_guid_t*);
gchar*	guid_to_str_buf(const e_guid_t*, gchar*, int);

WS_DLL_PUBLIC char *decode_bits_in_field(const guint bit_offset, const gint no_of_bits, const guint64 value);

WS_DLL_PUBLIC char	*other_decode_bitfield_value(char *buf, const guint32 val, const guint32 mask,
    const int width);
WS_DLL_PUBLIC char	*decode_bitfield_value(char *buf, const guint32 val, const guint32 mask,
    const int width);
WS_DLL_PUBLIC const char *decode_numeric_bitfield(const guint32 val, const guint32 mask, const int width,
  const char *fmt);

WS_DLL_PUBLIC const gchar* port_type_to_str (port_type type);

/** Turn an array of bytes into a string showing the bytes in hex.
 *
 * @param bd A pointer to the byte array
 * @param bd_len The length of the byte array
 * @return A pointer to the formatted string
 *
 * @see bytes_to_ep_str_punct()
 */
WS_DLL_PUBLIC gchar *bytes_to_ep_str(const guint8 *bd, int bd_len);

/** Turn an array of bytes into a string showing the bytes in hex,
 *  separated by a punctuation character.
 *
 * @param bd A pointer to the byte array
 * @param bd_len The length of the byte array
 * @param punct The punctuation character
 * @return A pointer to the formatted string
 *
 * @see bytes_to_ep_str()
 */
WS_DLL_PUBLIC gchar *bytes_to_ep_str_punct(const guint8 *bd, int bd_len, gchar punct);

/* Deprecated, use bytestring_to_str instead */
WS_DLL_PUBLIC const gchar *bytestring_to_ep_str(const guint8 *, const guint32, const char punct);

WS_DLL_PUBLIC const gchar *bytestring_to_str(wmem_allocator_t *scope, const guint8 *ad, const guint32 len, const char punct);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TO_STR_H__  */

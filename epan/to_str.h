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
#include <wsutil/inet_addr.h>
#include "time_fmt.h"
#include <epan/packet_info.h>
#include <epan/ipv6.h>
#include "ws_symbol_export.h"
#include "wmem/wmem.h"

#define GUID_STR_LEN     37
#define MAX_IP_STR_LEN   16
#define MAX_IP6_STR_LEN  WS_INET6_ADDRSTRLEN
#define MAX_ADDR_STR_LEN 256
#define VINES_ADDR_LEN   6
#define EUI64_STR_LEN    24
#define AX25_ADDR_LEN    7
#define FCWWN_ADDR_LEN   8

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * These are utility functions which convert various types to strings,
 * but for which no more specific module applies.
 */

WS_DLL_PUBLIC gchar* address_to_str(wmem_allocator_t *scope, const address *addr);
WS_DLL_PUBLIC gchar* address_with_resolution_to_str(wmem_allocator_t *scope, const address *addr);
WS_DLL_PUBLIC gchar* tvb_address_with_resolution_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const gint offset);

/*
 * address_to_name takes as input an "address", as defined in address.h.
 *
 * If the address is of a type that can be translated into a name, and the
 * user has activated name resolution, and the name can be resolved, it
 * returns a string containing the translated name.
 *
 * Otherwise, it returns NULL.
 */
WS_DLL_PUBLIC const gchar *address_to_name(const address *addr);

/*
 * address_to_display takes as input an "address", as defined in address.h .
 *
 * If the address is of a type that can be translated into a name, and the
 * user has activated name resolution, and the name can be resolved, it
 * returns a string containing the translated name.
 *
 * Otherwise, if the address is of type AT_NONE, it returns "NONE".
 *
 * Otherwise, it returns a string containing the result of address_to_str
 * on the argument, which should be a string representation for the address,
 * e.g. "10.10.10.10" for IPv4 address 10.10.10.10.
 */
WS_DLL_PUBLIC
gchar *address_to_display(wmem_allocator_t *allocator, const address *addr);

WS_DLL_PUBLIC void     address_to_str_buf(const address *addr, gchar *buf, int buf_len);

#define tvb_ether_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_ETHER, offset)
#define tvb_ip_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset)
#define tvb_ip6_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv6, offset)
#define tvb_fcwwn_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_FCWWN, offset)
#define tvb_fc_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_FC, offset)
#define tvb_eui64_to_str(tvb, offset) tvb_address_to_str(wmem_packet_scope(), tvb, AT_EUI64, offset)

void	ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len);
void	ip6_to_str_buf(const struct e_in6_addr *, gchar *, int buf_len);

extern gchar*	ipxnet_to_str_punct(wmem_allocator_t *scope, const guint32 ad, const char punct);
WS_DLL_PUBLIC gchar*	eui64_to_str(wmem_allocator_t *scope, const guint64 ad);

WS_DLL_PUBLIC gchar*	abs_time_to_str(wmem_allocator_t *scope, const nstime_t*, const absolute_time_display_e fmt,
    gboolean show_zone);
WS_DLL_PUBLIC gchar*	abs_time_secs_to_str(wmem_allocator_t *scope, const time_t, const absolute_time_display_e fmt,
    gboolean show_zone);
WS_DLL_PUBLIC void	display_epoch_time(gchar *, int, const time_t,  gint32, const to_str_time_res_t);

WS_DLL_PUBLIC void	display_signed_time(gchar *, int, const gint32, gint32, const to_str_time_res_t);

WS_DLL_PUBLIC gchar*	signed_time_secs_to_str(wmem_allocator_t *scope, const gint32 time_val);
WS_DLL_PUBLIC gchar*	unsigned_time_secs_to_str(wmem_allocator_t *scope, const guint32);
WS_DLL_PUBLIC gchar*	signed_time_msecs_to_str(wmem_allocator_t *scope, gint32 time_val);

extern void	guint32_to_str_buf(guint32 u, gchar *buf, int buf_len);
extern void	guint64_to_str_buf(guint64 u, gchar *buf, int buf_len);

WS_DLL_PUBLIC gchar*	rel_time_to_str(wmem_allocator_t *scope, const nstime_t*);
WS_DLL_PUBLIC gchar*	rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t*);
WS_DLL_PUBLIC gchar*	guid_to_str(wmem_allocator_t *scope, const e_guid_t*);
gchar*	guid_to_str_buf(const e_guid_t*, gchar*, int);

WS_DLL_PUBLIC char *decode_bits_in_field(const guint bit_offset, const gint no_of_bits, const guint64 value);

WS_DLL_PUBLIC const gchar* port_type_to_str (port_type type);

/** Turn an address type retrieved from a tvb into a string.
 *
 * @param scope memory allocation scheme used
 * @param tvb tvbuff to retrieve address
 * @param type address type to retrieve
 * @param offset offset into tvb to retrieve address
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC gchar* tvb_address_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const gint offset);

/** Turn an address type retrieved from a tvb into a string.
 *
 * @param scope memory allocation scheme used
 * @param tvb tvbuff to retrieve address
 * @param type address type to retrieve
 * @param offset offset into tvb to retrieve address
 * @param length The length of the string
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC gchar* tvb_address_var_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const gint offset, int length);

/**
 * word_to_hex()
 *
 * Output guint16 hex represetation to 'out', and return pointer after last character (out + 4).
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 4 bytes in the buffer.
 */
WS_DLL_PUBLIC char *word_to_hex(char *out, guint16 word);

/**
 * dword_to_hex()
 *
 * Output guint32 hex represetation to 'out', and return pointer after last character.
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 8 bytes in the buffer.
 */
WS_DLL_PUBLIC char *dword_to_hex(char *out, guint32 dword);

/** Turn an array of bytes into a string showing the bytes in hex.
 *
 * @param scope memory allocation scheme used
 * @param bd A pointer to the byte array
 * @param bd_len The length of the byte array
 * @return A pointer to the formatted string
 */
WS_DLL_PUBLIC char *bytes_to_str(wmem_allocator_t *scope, const guint8 *bd, int bd_len);

/** Turn an array of bytes into a string showing the bytes in hex,
 *  separated by a punctuation character.
 *
 * @param scope memory allocation scheme used
 * @param ad A pointer to the byte array
 * @param len The length of the byte array
 * @param punct The punctuation character
 * @return A pointer to the formatted string
 *
 * @see bytes_to_str()
 */
WS_DLL_PUBLIC gchar *bytestring_to_str(wmem_allocator_t *scope, const guint8 *ad, const guint32 len, const char punct);

/**
 * bytes_to_hexstr()
 *
 * Output hex represetation of guint8 ad array, and return pointer after last character.
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least len * 2 bytes in the buffer.
 */
WS_DLL_PUBLIC char *bytes_to_hexstr(char *out, const guint8 *ad, guint32 len);

/**
 * uint_to_str_back()
 *
 * Output guint32 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 10 bytes in the buffer.
 */
WS_DLL_PUBLIC char *uint_to_str_back(char *ptr, guint32 value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TO_STR_H__  */

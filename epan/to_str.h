/** @file
 * Definitions for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TO_STR_H__
#define __TO_STR_H__

#include <glib.h>

#include "wsutil/nstime.h"
#include <wsutil/inet_cidr.h>
#include <epan/proto.h>
#include <epan/packet_info.h>
#include "ws_symbol_export.h"
#include <epan/wmem_scopes.h>
#include <wsutil/to_str.h>

#define GUID_STR_LEN     37
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

/*
 ************** Address
 */

WS_DLL_PUBLIC char *address_to_str(wmem_allocator_t *scope, const address *addr);

WS_DLL_PUBLIC char *address_with_resolution_to_str(wmem_allocator_t *scope, const address *addr);

/*
 * address_to_name takes as input an "address", as defined in address.h.
 *
 * If the address is of a type that can be translated into a name, and the
 * user has activated name resolution, and the name can be resolved, it
 * returns a string containing the translated name.
 *
 * Otherwise, it returns NULL.
 */
WS_DLL_PUBLIC const char *address_to_name(const address *addr);

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
WS_DLL_PUBLIC char *address_to_display(wmem_allocator_t *allocator, const address *addr);

WS_DLL_PUBLIC void address_to_str_buf(const address *addr, char *buf, int buf_len);

WS_DLL_PUBLIC const char *port_type_to_str (port_type type);

/*
 ************** TVB
 */

WS_DLL_PUBLIC char* tvb_address_with_resolution_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const int offset);

#define tvb_ether_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_ETHER, offset)

#define tvb_ip_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_IPv4, offset)

#define tvb_ip6_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_IPv6, offset)

#define tvb_fcwwn_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_FCWWN, offset)

#define tvb_fc_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_FC, offset)

#define tvb_eui64_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_EUI64, offset)

/** Turn an address type retrieved from a tvb into a string.
 *
 * @param scope memory allocation scheme used
 * @param tvb tvbuff to retrieve address
 * @param type address type to retrieve
 * @param offset offset into tvb to retrieve address
 * @return A pointer to the formatted string
 *
 */
WS_DLL_PUBLIC char* tvb_address_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const int offset);

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
WS_DLL_PUBLIC char* tvb_address_var_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const int offset, int length);

/*
 ************** Time
 */

#define ABS_TIME_TO_STR_SHOW_ZONE       (1U << 0)
#define ABS_TIME_TO_STR_ADD_DQUOTES     (1U << 1)
#define ABS_TIME_TO_STR_SHOW_UTC_ONLY   (1U << 2)

WS_DLL_PUBLIC char *abs_time_to_str_ex(wmem_allocator_t *scope,
                                        const nstime_t *, field_display_e fmt,
                                        int flags);

#define abs_time_to_str(scope, nst, fmt, show_zone) \
        abs_time_to_str_ex(scope, nst, fmt, (show_zone) ? ABS_TIME_TO_STR_SHOW_ZONE : 0)

char *
abs_time_to_unix_str(wmem_allocator_t *scope, const nstime_t *rel_time);

WS_DLL_PUBLIC char *abs_time_secs_to_str_ex(wmem_allocator_t *scope,
                                        const time_t, field_display_e fmt,
                                        int flags);

#define abs_time_secs_to_str(scope, nst, fmt, show_zone) \
        abs_time_secs_to_str_ex(scope, nst, fmt, (show_zone) ? ABS_TIME_TO_STR_SHOW_ZONE : 0)

WS_DLL_PUBLIC char *signed_time_secs_to_str(wmem_allocator_t *scope, const int32_t time_val);

WS_DLL_PUBLIC char *unsigned_time_secs_to_str(wmem_allocator_t *scope, const uint32_t);

WS_DLL_PUBLIC char *signed_time_msecs_to_str(wmem_allocator_t *scope, int32_t time_val);

WS_DLL_PUBLIC char *rel_time_to_str(wmem_allocator_t *scope, const nstime_t *);

WS_DLL_PUBLIC char *rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t *);

/*
 ************** Misc
 */

WS_DLL_PUBLIC char *guid_to_str_buf(const e_guid_t *, char *, int);

WS_DLL_PUBLIC char *guid_to_str(wmem_allocator_t *scope, const e_guid_t *);

WS_DLL_PUBLIC char *decode_bits_in_field(wmem_allocator_t *scope, const unsigned bit_offset, const int no_of_bits, const uint64_t value, const unsigned encoding);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TO_STR_H__  */

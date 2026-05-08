/** @file
 * Definitions for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
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
#define EUI64_ADDR_LEN   8
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

/**
 * @brief Converts an address to a string.
 * @param scope Memory allocation scope for the resulting string.
 * @param addr The address to convert.
 * @return A string representation of the address.
 */
WS_DLL_PUBLIC char *address_to_str(wmem_allocator_t *scope, const address *addr);

/**
 * @brief Converts an address to a string with name resolution if possible.
 *
 * @param scope Memory allocation scope.
 * @param addr The address to convert.
 * @return A string containing the translated name or address string.
 */
WS_DLL_PUBLIC char *address_with_resolution_to_str(wmem_allocator_t *scope, const address *addr);

/**
 * @brief Converts an address to a name string if possible.
 *
 * address_to_name takes as input an "address", as defined in address.h.
 *
 * If the address is of a type that can be translated into a name, and the
 * user has activated name resolution, and the name can be resolved, it
 * returns a string containing the translated name.
 *
 * Otherwise, it returns NULL.
 *
 * @param addr The address to convert.
 * @return A string containing the translated name, or NULL if translation is not possible
 */
WS_DLL_PUBLIC const char *address_to_name(const address *addr);

/**
 * @brief Converts an address to a string representation to be displayed.
 *
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
 *
 * @param allocator Memory allocation scope for the resulting string.
 * @param addr The address to convert.
 * @return A string containing the translated name, "NONE", or a string representation of the address.
 */
WS_DLL_PUBLIC char *address_to_display(wmem_allocator_t *allocator, const address *addr);

/**
 * @brief Convert an address to a string buffer.
 *
 * @param addr The address structure to convert.
 * @param buf The buffer to store the resulting string.
 * @param buf_len The length of the buffer.
 */
WS_DLL_PUBLIC void address_to_str_buf(const address *addr, char *buf, int buf_len);

/**
 * @brief Converts a port type to its string representation.
 *
 * @param type The port type to convert.
 * @return const char* A string representing the port type.
 */
WS_DLL_PUBLIC const char *port_type_to_str (port_type type);

/*
 ************** TVB
 */

WS_DLL_PUBLIC char* tvb_address_with_resolution_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const unsigned offset);

#define tvb_ether_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_ETHER, offset)

#define tvb_ip_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_IPv4, offset)

#define tvb_ip6_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_IPv6, offset)

#define tvb_fcwwn_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_FCWWN, offset)

#define tvb_fc_to_str(scope, tvb, offset) tvb_address_to_str(scope, tvb, AT_FC, offset)

/* Note this assumes that the address is in network byte order, but
 * IEEE 802.15.4 puts EUI-64 addresses in reverse (Little Endian) order.
 */
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
WS_DLL_PUBLIC char* tvb_address_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, int type, const unsigned offset);

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
WS_DLL_PUBLIC char* tvb_address_var_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, address_type type, const unsigned offset, unsigned length);

/*
 ************** Time
 */

#define ABS_TIME_TO_STR_SHOW_ZONE       (1U << 0)
#define ABS_TIME_TO_STR_ADD_DQUOTES     (1U << 1)
#define ABS_TIME_TO_STR_SHOW_UTC_ONLY   (1U << 2)
#define ABS_TIME_TO_STR_ISO8601         (1U << 3)

/**
 * @brief Convert an absolute time to a string representation.
 *
 * Converts an absolute time to a human-readable string based on the specified format.
 *
 * @param scope Memory allocator scope for the returned string.
 * @param abs_time Pointer to the nstime_t structure representing the absolute time.
 * @param fmt The format of the output string (e.g., ABSOLUTE_TIME_LOCAL, ABSOLUTE_TIME_UNIX).
 * @param flags Additional flags that modify the formatting behavior.
 * @return A dynamically allocated string representing the formatted time.
 */
WS_DLL_PUBLIC char *abs_time_to_str_ex(wmem_allocator_t *scope,
                                        const nstime_t * abs_time, field_display_e fmt,
                                        int flags);

#define abs_time_to_str(scope, nst, fmt, show_zone) \
        abs_time_to_str_ex(scope, nst, fmt, (show_zone) ? ABS_TIME_TO_STR_SHOW_ZONE : 0)

/**
 * @brief Converts an absolute time to a Unix timestamp string.
 *
 * @param scope Memory allocation scope.
 * @param rel_time Relative time structure.
 * @return String representing the Unix timestamp.
 */
char *
abs_time_to_unix_str(wmem_allocator_t *scope, const nstime_t *rel_time);

/**
 * @brief Convert an absolute time in seconds to a string representation.
 *
 * @param scope Memory allocation scope for the resulting string.
 * @param abs_time_secs Absolute time in seconds.
 * @param fmt Format of the time string (e.g., ABSOLUTE_TIME_LOCAL).
 * @param flags Flags indicating additional formatting options.
 * @return String representation of the absolute time.
 */
WS_DLL_PUBLIC char *abs_time_secs_to_str_ex(wmem_allocator_t *scope,
                                        const time_t abs_time_secs, field_display_e fmt,
                                        int flags);

#define abs_time_secs_to_str(scope, nst, fmt, show_zone) \
        abs_time_secs_to_str_ex(scope, nst, fmt, (show_zone) ? ABS_TIME_TO_STR_SHOW_ZONE : 0)

/**
 * @brief Convert a signed value in seconds to a string.
 *
 * @param scope Memory allocation scope.
 * @param time_val Signed time value in seconds.
 * @return String representation of the time value.
 */
WS_DLL_PUBLIC char *signed_time_secs_to_str(wmem_allocator_t *scope, const int32_t time_val);

/**
 * @brief Convert an unsigned value in seconds to a string.
 *
 * @param scope Memory allocation scope.
 * @param time_val Time value in seconds.
 * @return String representation of the time value.
 */
WS_DLL_PUBLIC char *unsigned_time_secs_to_str(wmem_allocator_t *scope, const uint32_t time_val);

/**
 * @brief Convert a signed time value in milliseconds to a string.
 *
 * @param scope Memory allocation scope for the resulting string.
 * @param time_val Signed time value in milliseconds.
 * @return String representation of the time value.
 */
WS_DLL_PUBLIC char *signed_time_msecs_to_str(wmem_allocator_t *scope, int32_t time_val);

/**
 * @brief Convert a relative time to a string representation.
 *
 * @param scope Memory allocator scope for the resulting string.
 * @param rel_time Pointer to the nstime_t structure representing the relative time.
 * @return A dynamically allocated string representing the relative time in seconds and nanoseconds.
 */
WS_DLL_PUBLIC char *rel_time_to_str(wmem_allocator_t *scope, const nstime_t *rel_time);

/**
 * @brief Converts a relative time to a string representation in seconds.
 *
 * @param scope Memory allocation scope for the resulting string.
 * @param rel_time Pointer to the nstime_t structure representing the relative time.
 * @return A dynamically allocated string representing the time in seconds.
 */
WS_DLL_PUBLIC char *rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t *rel_time);

/*
 ************** Misc
 */

/**
 * @brief Convert a GUID to a string buffer.
 * @param guid Pointer to the GUID structure to convert.
 * @param buf Buffer to store the resulting string.
 * @param buf_len Length of the buffer.
 * @return A pointer to the buffer containing the string representation of the GUID.
 */
WS_DLL_PUBLIC char *guid_to_str_buf(const e_guid_t *guid, char *buf, int buf_len);

/**
 * @brief Convert a GUID to a string.
 *
 * @param scope Memory allocation scope.
 * @param guid Pointer to the GUID structure.
 * @return String representation of the GUID.
 */
WS_DLL_PUBLIC char *guid_to_str(wmem_allocator_t *scope, const e_guid_t *guid);

/**
 * @brief Decodes bits from a given offset and number of bits in a value.
 *
 * @param scope Memory allocator scope for allocating the result string.
 * @param bit_offset Offset within the value where decoding starts.
 * @param no_of_bits Number of bits to decode from the value.
 * @param value The 64-bit unsigned integer containing the bits to decode.
 * @param encoding Encoding type, such as little-endian or big-endian.
 * @return A string representing the decoded bits, or NULL on failure.
 */
WS_DLL_PUBLIC char *decode_bits_in_field(wmem_allocator_t *scope, const unsigned bit_offset, const int no_of_bits, const uint64_t value, const unsigned encoding);

#ifdef __cplusplus
}
#endif /* __cplusplus */

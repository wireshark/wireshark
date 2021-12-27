/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_INET_ADDR_H__
#define __WS_INET_ADDR_H__

#include <wireshark.h>

#include "inet_ipv4.h"
#include "inet_ipv6.h"

/*
 * These are the values specified by RFC 2133 and its successors for
 * INET_ADDRSTRLEN and INET6_ADDRSTRLEN.
 *
 * On UN*X systems, INET_ADDRSTRLEN and INET6_ADDRSTRLEN are defined
 * to the values from RFC 2133 and its successors.
 *
 * However, on Windows:
 *
 * There are APIs RtlIpv4AddressToStringEx(), which converts an
 * IPv4 address *and transport-layer port* to the address in the
 * standard text form, followed by a colon and the port number,
 * and RtlIpv6AddressToStringEx(), which converts an IPv6 address
 * *and scope ID and transport-layer port* to the address in the
 * standard text form, followed by a percent sign and the scope
 * ID (with the address and scope ID in square brackets), followed
 * by a colon and the port number.
 *
 * Instead of defining INET_ADDRSTRLEN_EX as 22 and INET6_ADDRSTRLEN_EX
 * as 65, and saying *those* were the buffer sizes to use for
 * RtlIpv4AddressToStringEx() and RtlIpv6AddressToStringEx(), they
 * defined INET_ADDRSTRLEN to be 22 and INET6_ADDRSTRLEN to be 65 - and
 * recommend using those as the size for the buffers passed to
 * RtlIpv4AddressToStringEx() and RtlIpv6AddressToStringEx().
 *
 * At least they document inet_ntop() as requiring a 16-byte or larger
 * buffer for IPv4 addresses and a 46-byte or larger buffer for
 * IPv6 addresses. For this reason, use hard-coded numeric constants rather than
 * INET_ADDRSTRLEN and INET6_ADDRSTRLEN.
 */
#define WS_INET_ADDRSTRLEN      16
#define WS_INET6_ADDRSTRLEN     46

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * To check for errors set errno to zero before calling ws_inet_ntop{4,6}.
 * ENOSPC is set if the result exceeds the given buffer size.
 */
WS_DLL_PUBLIC WS_RETNONNULL const char *
ws_inet_ntop4(const void *src, char *dst, size_t dst_size);

WS_DLL_PUBLIC WS_RETNONNULL const char *
ws_inet_ntop6(const void *src, char *dst, size_t dst_size);

WS_DLL_PUBLIC bool
ws_inet_pton4(const char *src, ws_in4_addr *dst);

WS_DLL_PUBLIC bool
ws_inet_pton6(const char *src, ws_in6_addr *dst);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

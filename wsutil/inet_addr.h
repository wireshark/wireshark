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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef uint32_t ws_in4_addr;	/* 32 bit IPv4 address, in network byte order */

typedef struct e_in6_addr {
    uint8_t bytes[16];           /* 128 bit IPv6 address */
} ws_in6_addr;


/**
 * Unicast Local
 * Returns true if the address is in the 224.0.0.0/24 local network
 * control block
 */
#define in4_addr_is_local_network_control_block(addr) \
  ((addr & 0xffffff00) == 0xe0000000)

/**
 * Multicast
 * Returns true if the address is in the 224.0.0.0/4 network block
 */
#define in4_addr_is_multicast(addr) \
  ((addr & 0xf0000000) == 0xe0000000)

/**
 * Private address
 * Returns true if the address is in one of the three blocks reserved
 * for private IPv4 addresses by section 3 of RFC 1918, namely:
 * 10/8, 172.16/12, and 192.168/16
 */
#define in4_addr_is_private(addr) \
  (((addr & 0xff000000) == 0x0a000000) || \
   ((addr & 0xfff00000) == 0xac100000) || \
   ((addr & 0xffff0000) == 0xc0a80000))

/**
 * Link-local address
 * Returns true if the address is in the 169.254/16 network block
 */
#define in4_addr_is_link_local(addr) \
  ((addr & 0xffff0000) == 0xa9fe0000)

/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
static inline bool
in6_addr_is_linklocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0x80);
}

static inline bool
in6_addr_is_sitelocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0xc0);
}

static inline bool in6_addr_is_uniquelocal(const ws_in6_addr *a)
{
    return (a->bytes[0] & 0xfe) == 0xfc;
}

/**
 * Multicast
 */
static inline bool
in6_addr_is_multicast(const ws_in6_addr *a)
{
    return a->bytes[0] == 0xff;
}

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

/*
 * Utility for CIDR notation of subnets
 */
#define WS_INET_CIDRADDRSTRLEN  19

/*
 * To check for errors set errno to zero before calling ws_inet_ntop{4,6}.
 * ENOSPC is set if the result exceeds the given buffer size.
 */
WS_DLL_PUBLIC WS_RETNONNULL
const char *
ws_inet_ntop4(const void *src, char *dst, size_t dst_size);

WS_DLL_PUBLIC WS_RETNONNULL
const char *
ws_inet_ntop6(const void *src, char *dst, size_t dst_size);

WS_DLL_PUBLIC
bool
ws_inet_pton4(const char *src, ws_in4_addr *dst);

WS_DLL_PUBLIC
bool
ws_inet_pton6(const char *src, ws_in6_addr *dst);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

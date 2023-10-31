/* iana-ip.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __IANA_IP_H__
#define __IANA_IP_H__

#include <wireshark.h>
#include <wsutil/inet_cidr.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum iana_ip {
    WS_IANA_IPv4 = 4,
    WS_IANA_IPv6 = 6,
};

struct ws_iana_ip_special_block {
    enum iana_ip type;
    union {
        ipv4_addr_and_mask ipv4;
        ipv6_addr_and_prefix ipv6;
    } u_ip;
    const char *name;
    /* true = 1; false = 0; n/a = -1 */
    int source, destination, forwardable, global, reserved;
};

WS_DLL_PUBLIC
const struct ws_iana_ip_special_block *
ws_iana_ipv4_special_block_lookup(uint32_t ipnum);

WS_DLL_PUBLIC
const struct ws_iana_ip_special_block *
ws_iana_ipv6_special_block_lookup(const ws_in6_addr *addr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

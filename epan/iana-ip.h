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
#include <ipv4.h>
#include <ipv6.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ws_ipv4_special_block {
    ipv4_addr_and_mask block;
    const char *name;
    /* true = 1; false = 0; n/a = -1 */
    int source, destination, forwardable, global, reserved;
};

struct ws_ipv6_special_block {
    ipv6_addr_and_prefix block;
    const char *name;
    /* true = 1; false = 0; n/a = -1 */
    int source, destination, forwardable, global, reserved;
};

WS_DLL_PUBLIC
const struct ws_ipv4_special_block *
ws_ipv4_special_block_lookup(const ws_in4_addr *addr);

WS_DLL_PUBLIC
const struct ws_ipv6_special_block *
ws_ipv6_special_block_lookup(const ws_in6_addr *addr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

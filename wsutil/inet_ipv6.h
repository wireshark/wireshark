/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __INET_IPV6_H__
#define __INET_IPV6_H__

#include <inttypes.h>
#include <stdbool.h>

#define IPv6_ADDR_SIZE  16

#define IPv6_HDR_SIZE           40
#define IPv6_FRAGMENT_HDR_SIZE  8

typedef struct e_in6_addr {
    uint8_t bytes[16];           /* 128 bit IPv6 address */
} ws_in6_addr;

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */
struct ws_ip6_hdr {
    uint32_t    ip6h_vc_flow;           /* version, class, flow */
    uint16_t    ip6h_plen;              /* payload length */
    uint8_t     ip6h_nxt;               /* next header */
    uint8_t     ip6h_hlim;              /* hop limit */
    ws_in6_addr ip6h_src;               /* source address */
    ws_in6_addr ip6h_dst;               /* destination address */
};

/*
 * Extension Headers
 */

struct ip6_ext {
    unsigned char ip6e_nxt;
    unsigned char ip6e_len;
};

/* Routing header */
struct ip6_rthdr {
    uint8_t ip6r_nxt;        /* next header */
    uint8_t ip6r_len;        /* length in units of 8 octets */
    uint8_t ip6r_type;       /* routing type */
    uint8_t ip6r_segleft;    /* segments left */
    /* followed by routing type specific data */
};

/* Type 0 Routing header */
struct ip6_rthdr0 {
    uint8_t ip6r0_nxt;       /* next header */
    uint8_t ip6r0_len;       /* length in units of 8 octets */
    uint8_t ip6r0_type;      /* always zero */
    uint8_t ip6r0_segleft;   /* segments left */
    uint8_t ip6r0_reserved;  /* reserved field */
    uint8_t ip6r0_slmap[3];  /* strict/loose bit map */
    /* followed by up to 127 addresses */
    ws_in6_addr ip6r0_addr[1];
};

/* Fragment header */
struct ip6_frag {
    uint8_t ip6f_nxt;       /* next header */
    uint8_t ip6f_reserved;  /* reserved field */
    uint16_t ip6f_offlg;     /* offset, reserved, and flag */
    uint32_t ip6f_ident;     /* identification */
};

#define IP6F_OFF_MASK           0xfff8 /* mask out offset from _offlg */
#define IP6F_RESERVED_MASK      0x0006 /* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG          0x0001 /* more-fragments flag */


/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
static inline bool in6_addr_is_linklocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0x80);
}

static inline bool in6_addr_is_sitelocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0xc0);
}

/**
 * Multicast
 */
static inline bool in6_addr_is_multicast(const ws_in6_addr *a)
{
    return a->bytes[0] == 0xff;
}

#endif

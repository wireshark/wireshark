/* packet_endpoints.c
 * Find the transport endpoints of a raw packet
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "packet_endpoints.h"

#include <string.h>

/* LINKTYPE_ values, as in pcap file headers and pcapng IDBs. */
#define LINKTYPE_NULL            0
#define LINKTYPE_ETHERNET        1
#define DLT_RAW_ON_MOST_SYSTEMS 12   /* the DLT_ value, which some writers use instead of the LINKTYPE_ value */
#define LINKTYPE_RAW           101
#define LINKTYPE_LOOP          108
#define LINKTYPE_LINUX_SLL     113
#define LINKTYPE_IPV4          228
#define LINKTYPE_IPV6          229
#define LINKTYPE_LINUX_SLL2    276

#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_IPV6      0x86DD
#define ETHERTYPE_VLAN      0x8100
#define ETHERTYPE_QINQ      0x88A8
#define ETHERTYPE_QINQ_OLD  0x9100

#define IP_PROTO_HOPOPTS     0
#define IP_PROTO_TCP         6
#define IP_PROTO_UDP        17
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_AH         51
#define IP_PROTO_DSTOPTS    60

#define NOT_IP SIZE_MAX

static uint16_t
get_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

bool
ws_packet_endpoints_linktype_supported(int linktype)
{
    switch (linktype) {
    case LINKTYPE_NULL:
    case LINKTYPE_ETHERNET:
    case DLT_RAW_ON_MOST_SYSTEMS:
    case LINKTYPE_RAW:
    case LINKTYPE_LOOP:
    case LINKTYPE_LINUX_SLL:
    case LINKTYPE_IPV4:
    case LINKTYPE_IPV6:
    case LINKTYPE_LINUX_SLL2:
        return true;
    default:
        return false;
    }
}

/*
 * Skip the link-layer header, and any VLAN tags, of a packet that carries
 * IP; returns the offset of the IP header, or NOT_IP.
 */
static size_t
skip_link_header(int linktype, const uint8_t *data, size_t len)
{
    size_t offset;
    uint16_t ethertype;

    switch (linktype) {
    case LINKTYPE_NULL:
    case LINKTYPE_LOOP:
        /* A 4-byte address family, in either byte order; the IP version says what follows. */
        return 4;
    case DLT_RAW_ON_MOST_SYSTEMS:
    case LINKTYPE_RAW:
    case LINKTYPE_IPV4:
    case LINKTYPE_IPV6:
        return 0;
    case LINKTYPE_ETHERNET:
        if (len < 14)
            return NOT_IP;
        ethertype = get_be16(data + 12);
        offset = 14;
        break;
    case LINKTYPE_LINUX_SLL:
        if (len < 16)
            return NOT_IP;
        ethertype = get_be16(data + 14);
        offset = 16;
        break;
    case LINKTYPE_LINUX_SLL2:
        if (len < 20)
            return NOT_IP;
        ethertype = get_be16(data);
        offset = 20;
        break;
    default:
        return NOT_IP;
    }

    while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ ||
           ethertype == ETHERTYPE_QINQ_OLD) {
        if (len < offset + 4)
            return NOT_IP;
        ethertype = get_be16(data + offset + 2);
        offset += 4;
    }
    if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
        return NOT_IP;
    return offset;
}

bool
ws_packet_endpoints_parse(int linktype, const uint8_t *data, size_t len,
                          ws_packet_endpoints_t *endpoints)
{
    size_t offset, transport;
    const uint8_t *ip;
    uint8_t protocol;

    offset = skip_link_header(linktype, data, len);
    if (offset == NOT_IP || len <= offset)
        return false;
    ip = data + offset;
    memset(endpoints, 0, sizeof *endpoints);

    switch (ip[0] >> 4) {
    case 4: {
        size_t header_len;

        if (len < offset + 20)
            return false;
        header_len = (size_t)(ip[0] & 0x0f) * 4;
        if (header_len < 20 || len < offset + header_len)
            return false;
        if ((get_be16(ip + 6) & 0x1fff) != 0)
            return false;  /* a later fragment: no ports */
        protocol = ip[9];
        endpoints->src.ip_version = 4;
        endpoints->dst.ip_version = 4;
        memcpy(&endpoints->src.addr.ipv4, ip + 12, 4);
        memcpy(&endpoints->dst.addr.ipv4, ip + 16, 4);
        transport = offset + header_len;
        break;
    }
    case 6:
        if (len < offset + 40)
            return false;
        protocol = ip[6];
        endpoints->src.ip_version = 6;
        endpoints->dst.ip_version = 6;
        memcpy(endpoints->src.addr.ipv6.bytes, ip + 8, 16);
        memcpy(endpoints->dst.addr.ipv6.bytes, ip + 24, 16);
        transport = offset + 40;
        /* Step over the extension headers. */
        while (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP) {
            size_t ext_len;

            switch (protocol) {
            case IP_PROTO_HOPOPTS:
            case IP_PROTO_ROUTING:
            case IP_PROTO_DSTOPTS:
                if (len < transport + 2)
                    return false;
                ext_len = ((size_t)data[transport + 1] + 1) * 8;
                break;
            case IP_PROTO_FRAGMENT:
                if (len < transport + 8)
                    return false;
                if ((get_be16(data + transport + 2) & 0xfff8) != 0)
                    return false;  /* a later fragment: no ports */
                ext_len = 8;
                break;
            case IP_PROTO_AH:
                if (len < transport + 2)
                    return false;
                ext_len = ((size_t)data[transport + 1] + 2) * 4;
                break;
            default:
                return false;  /* not TCP or UDP, or ESP hides the ports */
            }
            protocol = data[transport];
            transport += ext_len;
        }
        break;
    default:
        return false;
    }

    if (protocol == IP_PROTO_TCP)
        endpoints->protocol = WS_PROCESS_LOOKUP_TCP;
    else if (protocol == IP_PROTO_UDP)
        endpoints->protocol = WS_PROCESS_LOOKUP_UDP;
    else
        return false;
    if (len < transport + 4)
        return false;
    endpoints->src.port = get_be16(data + transport);
    endpoints->dst.port = get_be16(data + transport + 2);
    return true;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

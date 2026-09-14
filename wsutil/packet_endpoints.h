/** @file
 *
 * Find the transport endpoints of a raw packet: the IP addresses,
 * transport protocol and ports of a TCP or UDP packet, given the
 * link-layer header type it was captured with.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_PACKET_ENDPOINTS_H__
#define __WSUTIL_PACKET_ENDPOINTS_H__

#include <wireshark.h>
#include <wsutil/process_lookup.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** The transport endpoints of a packet. */
typedef struct ws_packet_endpoints {
    ws_process_lookup_protocol_t protocol;  /**< WS_PROCESS_LOOKUP_TCP or WS_PROCESS_LOOKUP_UDP */
    ws_socket_endpoint_t         src;       /**< The sender */
    ws_socket_endpoint_t         dst;       /**< The receiver */
} ws_packet_endpoints_t;

/**
 * @brief Whether packets with a link-layer header type can be parsed.
 *
 * @param linktype The LINKTYPE_ value, as in a pcapng Interface Description
 * Block or a pcap file header.
 * @return true for Ethernet, the BSD loopback encapsulations, Linux cooked
 * capture v1 and v2, and raw IPv4 or IPv6.
 */
WS_DLL_PUBLIC bool
ws_packet_endpoints_linktype_supported(int linktype);

/**
 * @brief Find the endpoints of a TCP or UDP packet.
 *
 * Handles Ethernet, with any 802.1Q or 802.1ad VLAN tags, the BSD loopback
 * encapsulations (LINKTYPE_NULL and LINKTYPE_LOOP), Linux cooked capture
 * v1 and v2, and raw IPv4 or IPv6, followed by an IPv4 header, or an IPv6
 * header with any hop-by-hop, routing, destination options, fragment and
 * authentication headers, and then a TCP or UDP header.
 *
 * @param linktype The LINKTYPE_ value of the packet.
 * @param data The packet data.
 * @param len The number of bytes of packet data captured.
 * @param endpoints Filled in on success.
 * @return true if the packet is a TCP or UDP packet whose ports are present,
 * i.e. it is not a later fragment and was not cut off before the ports.
 */
WS_DLL_PUBLIC bool
ws_packet_endpoints_parse(int linktype, const uint8_t *data, size_t len,
                          ws_packet_endpoints_t *endpoints);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_PACKET_ENDPOINTS_H__ */

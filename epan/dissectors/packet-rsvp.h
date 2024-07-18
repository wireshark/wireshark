/* packet-rsvp.h
 * Declarations of variables exported by "packet-rsvp.c"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RSVP_H
#define PACKET_RSVP_H

/* RSVP conversations support */
typedef struct rsvp_conversation_info
{
    uint8_t session_type;
    address source;
    address destination;
    uint16_t udp_source_port;
    uint16_t udp_dest_port;
    uint8_t protocol;
    uint32_t ext_tunnel_id;
    uint64_t ext_tunnel_id_ipv6_pre;
    uint64_t ext_tunnel_id_ipv6_post;
    uint8_t dscp;
} rsvp_conversation_info;

extern const range_string gmpls_switching_type_rvals[];
extern const range_string gmpls_lsp_enc_rvals[];
extern const value_string gmpls_protection_cap_str[];
extern value_string_ext gmpls_sonet_signal_type_str_ext;

#endif

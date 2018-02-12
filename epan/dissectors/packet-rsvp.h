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
    guint8 session_type;
    address source;
    address destination;
    guint16 udp_source_port;
    guint16 udp_dest_port;
    guint8  protocol;
    guint32 ext_tunnel_id;
    guint64 ext_tunnel_id_ipv6_pre;
    guint64 ext_tunnel_id_ipv6_post;
    guint8 dscp;
} rsvp_conversation_info;

extern const range_string gmpls_switching_type_rvals[];
extern const range_string gmpls_lsp_enc_rvals[];
extern const value_string gmpls_protection_cap_str[];
extern value_string_ext gmpls_sonet_signal_type_str_ext;

#endif

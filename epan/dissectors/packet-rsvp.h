/* packet-rsvp.h
 * Declarations of variables exported by "packet-rsvp.c"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

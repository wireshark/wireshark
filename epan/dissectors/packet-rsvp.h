/* packet-rsvp.h
 * Declarations of variables exported by "packet-rsvp.c"
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
} rsvp_conversation_info;

extern const value_string gmpls_switching_type_str[];
extern const value_string gmpls_lsp_enc_str[];
extern const value_string gmpls_protection_cap_str[];
extern const value_string gmpls_sonet_signal_type_str[];

#endif

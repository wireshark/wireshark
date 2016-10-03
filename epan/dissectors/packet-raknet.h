/* packet-raknet.h
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

#ifndef __PACKET_RAKNET_H__
#define __PACKET_RAKNET_H__

#include <epan/packet.h>
#include "ws_symbol_export.h"

/*
 * Different protocols (i.e. games) use different set of message IDs,
 * and we can't infer protocols from message ID because there is no
 * central registry. So the only thing we can do is to use port number
 * or heuristics to determine the protocol.
 *
 * If your protocol has a fixed port number, you can register it with
 * this function. The registered dissector will be called with a tvb
 * buffer which contains a RakNet message including message ID at its
 * first octet. Header analysis, packet reassembly, and RakNet system
 * messages are all handled by the RakNet dissector so you don't need
 * to worry about them.
 */
WS_DLL_PUBLIC
void
raknet_add_udp_dissector(guint32 port, const dissector_handle_t handle);

/*
 * Opposite of "raknet_add_udp_dissector()".
 */
WS_DLL_PUBLIC
void
raknet_delete_udp_dissector(guint32 port, const dissector_handle_t handle);

/*
 * You can also register a heuristic dissector for your protocol with
 * the standard "heur_dissector_add()" function with parent protocol
 * "raknet". Protocols with no fixed port are especially encouraged to
 * do so. Once your heuristic dissector finds that the protocol of the
 * conversation is indeed yours, call this function to skip further
 * heuristics. DO NOT USE the standard "conversation_set_dissector()".
 */
WS_DLL_PUBLIC
void
raknet_conversation_set_dissector(packet_info *pinfo, const dissector_handle_t handle);

#endif /* __PACKET_RAKNET_H__ */

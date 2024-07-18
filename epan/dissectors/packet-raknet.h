/* packet-raknet.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
raknet_add_udp_dissector(uint32_t port, const dissector_handle_t handle);

/*
 * Opposite of "raknet_add_udp_dissector()".
 */
WS_DLL_PUBLIC
void
raknet_delete_udp_dissector(uint32_t port, const dissector_handle_t handle);

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

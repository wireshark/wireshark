/* packet-sapni.h
 * Routines for SAP NI (Network Interface) dissection
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SAPPROTOCOL_H__
#define __PACKET_SAPPROTOCOL_H__

#include <epan/packet.h>

extern void
dissect_sap_protocol_payload(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, guint16 sport, guint16 dport);

#endif /* __PACKET_SAPPROTOCOL_H__ */

/* packet-bt-utp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BT_UTP_H__
#define __PACKET_BT_UTP_H__

#include "ws_symbol_export.h"

#include <epan/conversation.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* bittorent is the only protocol on uTP, so extern not WS_DLL_PUBLIC */
extern void
utp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 bool proto_desegment, unsigned fixed_len,
                 unsigned (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
                 dissector_t dissect_pdu, void* dissector_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

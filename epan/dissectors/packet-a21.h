/* packet-a21.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_A21_H__
#define __PACKET_A21_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "ws_symbol_export.h"

WS_DLL_PUBLIC
void dissect_a21_ie_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, proto_tree *tree, gint offset, guint8 message_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

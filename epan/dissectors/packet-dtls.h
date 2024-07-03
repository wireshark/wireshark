/* packet-dtls.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DTLS_H__
#define __PACKET_DTLS_H__

#include "ws_symbol_export.h"
#include <epan/packet.h>

WS_DLL_PUBLIC void dtls_dissector_add(unsigned port, dissector_handle_t handle);
WS_DLL_PUBLIC void dtls_dissector_delete(unsigned port, dissector_handle_t handle);


/* Shared with packet-tls-utils.c */

int
dtls_dissect_hnd_hello_ext_use_srtp(packet_info *pinfo, tvbuff_t *tvb,
                                    proto_tree *tree, uint32_t offset,
                                    uint32_t ext_len, bool is_server);

#endif  /* __PACKET_DTLS_H__ */

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

WS_DLL_PUBLIC void dtls_dissector_add(guint port, dissector_handle_t handle);
WS_DLL_PUBLIC void dtls_dissector_delete(guint port, dissector_handle_t handle);


/* Shared with packet-tls-utils.c */

gint
dtls_dissect_hnd_hello_ext_use_srtp(tvbuff_t *tvb, proto_tree *tree,
                                    guint32 offset, guint32 ext_len);

#endif  /* __PACKET_DTLS_H__ */

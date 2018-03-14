/* packet-ssl.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SSL_H__
#define __PACKET_SSL_H__

#include "ws_symbol_export.h"
#include <epan/packet.h>

/** Maps Session-ID to pre-master secrets. */
WS_DLL_PUBLIC GHashTable *ssl_session_hash;
/** Maps Client Random to pre-master secrets. */
WS_DLL_PUBLIC GHashTable *ssl_crandom_hash;

WS_DLL_PUBLIC void ssl_dissector_add(guint port, dissector_handle_t handle);
WS_DLL_PUBLIC void ssl_dissector_delete(guint port, dissector_handle_t handle);

WS_DLL_PUBLIC void ssl_set_master_secret(guint32 frame_num, address *addr_srv, address *addr_cli,
                                  port_type ptype, guint32 port_srv, guint32 port_cli,
                                  guint32 version, gint cipher, const guchar *_master_secret,
                                  const guchar *_client_random, const guchar *_server_random,
                                  guint32 client_seq, guint32 server_seq);

#endif  /* __PACKET_SSL_H__ */

/* packet-tls.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TLS_H__
#define __PACKET_TLS_H__

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
/**
 * Retrieves Libgcrypt identifiers for the current TLS cipher. Only valid after
 * the Server Hello has been processed and if the current conversation has TLS.
 * Alternatively, this conversation lookup can be skipped if the current cipher
 * ('cipher_suite') is provided (non-zero).
 */
extern gboolean
tls_get_cipher_info(packet_info *pinfo, guint16 cipher_suite, int *cipher_algo, int *cipher_mode, int *hash_algo);

/**
 * Computes the TLS 1.3 "TLS-Exporter(label, context_value, key_length)" value.
 * On success, the secret is in "out" (free with "wmem_free(NULL, out)").
 */
gboolean
tls13_exporter(packet_info *pinfo, gboolean is_early,
               const char *label, guint8 *context,
               guint context_length, guint key_length, guchar **out);

gint
tls13_get_quic_secret(packet_info *pinfo, gboolean is_from_server, int type, guint secret_min_len, guint secret_max_len, guint8 *secret_out);

/**
 * Returns the application-layer protocol name (ALPN) for the current TLS
 * session, or NULL if unavailable.
 */
const char *
tls_get_alpn(packet_info *pinfo);

#endif  /* __PACKET_TLS_H__ */
